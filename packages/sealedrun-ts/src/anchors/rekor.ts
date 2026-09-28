import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { hexDecode, hexEncode } from "../encoding.js";
import { selectWitnesses, type Witness, witnessCovers } from "../trust.js";

/** `rekor` receipt as stored in an anchor record (SPEC 8.1.2). */
export interface RekorReceipt {
  digest: string;
  log_url: string;
  uuid: string;
  log_index: number;
  log_id: string;
  integrated_time?: number;
  /** Base64 canonical entry. */
  body: string;
  signed_entry_timestamp?: string;
  inclusion_proof: {
    log_index: number;
    root_hash: string;
    tree_size: number;
    hashes: string[];
    checkpoint: string;
  };
  /** PEM public key of the anchoring key. */
  public_key: string;
  /** Base64 DER ECDSA signature, digest as the prehashed message. */
  signature: string;
}

/** DER prefix of a P-256 SubjectPublicKeyInfo, followed by the 65-byte uncompressed point. */
const SPKI_P256_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
const SIGNATURE_LINE = /^— (\S+) (\S+)$/;

/**
 * Verifies a `rekor` receipt obtained from `witness` against the trust list (SPEC 8.4),
 * offline, on `@noble/curves`.
 *
 * @remarks
 * Checks: the trust entry's log key has the receipt's `log_id`; the entry body decodes to a
 * `hashedrekord` over `digest` signed with `public_key`; the anchoring signature verifies with
 * `digest` as the prehashed message; when `integrated_time` is present it lies within the
 * entry's validity and the signed entry timestamp verifies with the log key over the canonical
 * `{body, integratedTime, logID, logIndex}`; the RFC 6962 inclusion path from
 * `SHA-256(0x00 || body)` reaches `root_hash`; the checkpoint is a C2SP signed note whose line
 * with the log's 4-byte key hint verifies with the log key and whose size and root equal the
 * proof's. Cosignature lines of other keys are ignored.
 *
 * @returns False when no trust entry matches or any check fails; never throws on bad input.
 */
export async function verifyRekor(
  receipt: RekorReceipt,
  witness: string,
  trust: Witness[],
): Promise<boolean> {
  const entries = selectWitnesses(trust, "rekor", witness, receipt.log_id);
  for (const entry of entries) {
    try {
      if (verifyWith(receipt, entry)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

function verifyWith(receipt: RekorReceipt, entry: Witness): boolean {
  if (entry.publicKey === undefined) return false;
  const logDer = pemDecode(entry.publicKey, "PUBLIC KEY");
  const logId = hexEncode(sha256(logDer));
  if (receipt.log_id !== logId || (entry.logId !== undefined && entry.logId !== logId)) {
    return false;
  }
  const logKey = pointOf(logDer);
  const anchoringKey = pointOf(pemDecode(receipt.public_key, "PUBLIC KEY"));
  if (!logKey || !anchoringKey) return false;

  const body = base64Decode(receipt.body);
  const fields = bodyFields(body);
  if (!fields || fields.digest !== receipt.digest || fields.publicKey !== receipt.public_key) {
    return false;
  }
  const head = hexDecode(receipt.digest);
  if (head.length !== 32) return false;
  if (
    !p256.verify(base64Decode(receipt.signature), head, anchoringKey, {
      prehash: false,
      format: "der",
      lowS: false,
    })
  ) {
    return false;
  }

  if (receipt.integrated_time !== undefined) {
    if (!witnessCovers(entry, new Date(receipt.integrated_time * 1000))) return false;
    if (receipt.signed_entry_timestamp === undefined) return false;
    const signed = new TextEncoder().encode(
      `{"body":${JSON.stringify(receipt.body)},"integratedTime":${receipt.integrated_time},"logID":${JSON.stringify(receipt.log_id)},"logIndex":${receipt.log_index}}`,
    );
    if (
      !p256.verify(base64Decode(receipt.signed_entry_timestamp), signed, logKey, {
        prehash: true,
        format: "der",
        lowS: false,
      })
    ) {
      return false;
    }
  }

  const proof = receipt.inclusion_proof;
  const leaf = sha256(concat(new Uint8Array([0]), body));
  const root = rootFromPath(leaf, proof.log_index, proof.tree_size, proof.hashes);
  if (hexEncode(root) !== proof.root_hash) return false;
  const checkpoint = verifyCheckpoint(proof.checkpoint, logKey, logId);
  return checkpoint.size === proof.tree_size && hexEncode(checkpoint.root) === proof.root_hash;
}

function bodyFields(body: Uint8Array): { digest: string; publicKey: string } | null {
  const doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as {
    kind?: string;
    spec?: {
      data?: { hash?: { algorithm?: string; value?: string } };
      signature?: { publicKey?: { content?: string } };
    };
  };
  if (doc.kind !== "hashedrekord" || doc.spec?.data?.hash?.algorithm !== "sha256") return null;
  const digest = doc.spec.data.hash.value;
  const content = doc.spec.signature?.publicKey?.content;
  if (typeof digest !== "string" || typeof content !== "string") return null;
  return { digest, publicKey: new TextDecoder().decode(base64Decode(content)) };
}

/** RFC 6962 inclusion proof: folds the sibling hashes from the leaf up to the root. */
function rootFromPath(leaf: Uint8Array, index: number, size: number, hashes: string[]): Uint8Array {
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) {
    throw new RangeError("leaf index outside the tree");
  }
  const path = hashes.map(hexDecode);
  const inner = bitLength(index ^ (size - 1));
  const border = popCount(Math.floor(index / 2 ** inner));
  if (path.length !== inner + border) throw new RangeError("proof length does not fit the tree");
  let node = leaf;
  for (let i = 0; i < inner; i += 1) {
    const sibling = path[i];
    if (!sibling) throw new RangeError("proof shorter than announced");
    node = Math.floor(index / 2 ** i) % 2 === 1 ? hashNode(sibling, node) : hashNode(node, sibling);
  }
  for (const sibling of path.slice(inner)) node = hashNode(sibling, node);
  return node;
}

function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(new Uint8Array([1]), left, right));
}

/**
 * Parses a C2SP signed note and verifies the log's signature line. The note body is everything
 * up to and including the blank line; the log's key hint is the first four bytes of `logId`.
 */
function verifyCheckpoint(
  text: string,
  logKey: Uint8Array,
  logId: string,
): { origin: string; size: number; root: Uint8Array } {
  const split = text.indexOf("\n\n");
  if (split < 0) throw new SyntaxError("checkpoint has no signature lines");
  const body = text.slice(0, split);
  const [origin, sizeText, rootText] = body.split("\n");
  if (origin === undefined || sizeText === undefined || rootText === undefined) {
    throw new SyntaxError("checkpoint body too short");
  }
  const size = Number(sizeText);
  if (!Number.isSafeInteger(size)) throw new SyntaxError("checkpoint size is not an integer");
  const root = base64Decode(rootText);
  const hint = hexDecode(logId).subarray(0, 4);
  const message = new TextEncoder().encode(body + "\n");
  for (const line of text.slice(split + 2).split("\n")) {
    if (line === "") continue;
    const match = SIGNATURE_LINE.exec(line);
    const encoded = match?.[2];
    if (encoded === undefined) throw new SyntaxError("malformed signature line");
    const blob = base64Decode(encoded);
    if (hexEncode(blob.subarray(0, 4)) !== hexEncode(hint)) continue;
    if (
      !p256.verify(blob.subarray(4), message, logKey, {
        prehash: true,
        format: "der",
        lowS: false,
      })
    ) {
      throw new Error("checkpoint signature invalid");
    }
    return { origin, size, root };
  }
  throw new Error("no signature by the log on the checkpoint");
}

/** The uncompressed point of a P-256 SubjectPublicKeyInfo, or null for any other key. */
function pointOf(der: Uint8Array): Uint8Array | null {
  const hex = hexEncode(der);
  if (der.length !== 91 || !hex.startsWith(SPKI_P256_PREFIX) || der[26] !== 0x04) return null;
  return der.subarray(26);
}

function pemDecode(pem: string, label: string): Uint8Array {
  const body = pem
    .replace(`-----BEGIN ${label}-----`, "")
    .replace(`-----END ${label}-----`, "")
    .replace(/\s+/g, "");
  return base64Decode(body);
}

function base64Decode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new SyntaxError("invalid base64");
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bitLength(value: number): number {
  return value === 0 ? 0 : Math.floor(Math.log2(value)) + 1;
}

function popCount(value: number): number {
  let count = 0;
  for (let v = value; v > 0; v = Math.floor(v / 2)) count += v % 2;
  return count;
}
