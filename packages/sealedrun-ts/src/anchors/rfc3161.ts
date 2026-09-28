import { sha256 } from "@noble/hashes/sha2.js";
import * as pkijs from "pkijs";

import { hexDecode, hexEncode } from "../encoding.js";
import { parseTimestamp } from "../time.js";
import { selectWitnesses, type Witness, witnessCovers } from "../trust.js";

const ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4";
const ID_SHA256 = "2.16.840.1.101.3.4.2.1";
const ID_CE_EXT_KEY_USAGE = "2.5.29.37";
const ID_CE_BASIC_CONSTRAINTS = "2.5.29.19";
const ID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";

/** `rfc3161` receipt as stored in an anchor record (SPEC 8.1.1). */
export interface Rfc3161Receipt {
  digest: string;
  imprint_alg: string;
  /** Base64 DER TimeStampToken (CMS SignedData). */
  token: string;
  /** PEM certificates published by the authority, untrusted snapshot. */
  chain: string[];
  /** Decimal request nonce. */
  nonce: string;
  gen_time?: string;
  policy?: string;
}

/**
 * Verifies an `rfc3161` receipt obtained from `witness` against the trust list (SPEC 8.4), on
 * WebCrypto, so it runs in browsers and Node alike.
 *
 * @remarks
 * Checks, in order: the token is CMS SignedData over a TSTInfo with a SHA-256 imprint of the raw
 * `digest` bytes and the receipt's nonce; `gen_time` and `policy`, when present, match the
 * token; the signer is the certificate named by the SignerInfo signer identifier, found in the
 * token or in `chain`, carries the critical time-stamping extended key usage, and its CMS
 * signature over the signed attributes verifies; a chain from it through the token's and the
 * receipt's certificates reaches a root of a matching trust entry, all valid at `genTime`;
 * `genTime` lies within the entry's validity. The signer is matched byte for byte the way pkijs
 * does, and the certificate pkijs actually verified must be that signer. Only authorities whose
 * signatures lead back to a trust root take part in path building, so a receipt can neither
 * smuggle in a root nor make path building loop. pkijs recognises the TSTInfo content type and
 * re-checks the imprint against the raw digest bytes passed as `data`.
 *
 * @returns False when no trust entry matches the witness or any check fails; never throws on
 * bad input.
 */
export async function verifyRfc3161(
  receipt: Rfc3161Receipt,
  witness: string,
  trust: Witness[],
): Promise<boolean> {
  const entries = selectWitnesses(trust, "rfc3161", witness);
  if (entries.length === 0) return false;
  for (const entry of entries) {
    try {
      if (await verifyWith(receipt, entry)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

async function verifyWith(receipt: Rfc3161Receipt, entry: Witness): Promise<boolean> {
  if (receipt.imprint_alg !== "sha256") return false;
  const token = pkijs.ContentInfo.fromBER(base64Decode(receipt.token));
  if (token.contentType !== ID_SIGNED_DATA) return false;
  const signed = new pkijs.SignedData({ schema: token.content });
  if (signed.encapContentInfo.eContentType !== ID_CT_TSTINFO) return false;
  const content = signed.encapContentInfo.eContent;
  if (!content) return false;
  const info = pkijs.TSTInfo.fromBER(content.valueBlock.valueHexView.slice());

  const genTime = info.genTime;
  if (!witnessCovers(entry, genTime)) return false;
  if (receipt.gen_time !== undefined && parseTimestamp(receipt.gen_time) !== genTime.getTime()) {
    return false;
  }
  if (receipt.policy !== undefined && info.policy !== receipt.policy) return false;
  if (info.messageImprint.hashAlgorithm.algorithmId !== ID_SHA256) return false;
  const imprint = hexEncode(sha256(hexDecode(receipt.digest)));
  if (
    hexEncode(new Uint8Array(info.messageImprint.hashedMessage.valueBlock.valueHexView)) !== imprint
  ) {
    return false;
  }
  if (!/^\d+$/.test(receipt.nonce)) return false;
  if (info.nonce === undefined || info.nonce.toBigInt() !== BigInt(receipt.nonce)) return false;

  if (signed.signerInfos.length !== 1) return false;
  const signer = signed.signerInfos[0];
  if (!signer) return false;
  const sid = signer.sid as unknown;
  if (!(sid instanceof pkijs.IssuerAndSerialNumber)) return false;

  const roots = entry.roots.map((pem) => pkijs.Certificate.fromBER(pemDecode(pem)));
  const rootDer = new Set(roots.map(der));
  const offered = receipt.chain.map((pem) => pkijs.Certificate.fromBER(pemDecode(pem)));
  const embedded = (signed.certificates ?? []).filter(
    (c): c is pkijs.Certificate => c instanceof pkijs.Certificate,
  );
  const candidates = [...embedded, ...offered];
  if (candidates.length > MAX_CERTIFICATES) return false;
  const leaf = candidates.find(
    (c) => c.issuer.isEqual(sid.issuer) && c.serialNumber.isEqual(sid.serialNumber),
  );
  if (!leaf || !hasTimeStampingUsage(leaf)) return false;
  const authorities = await issuedUnder(roots, candidates.filter(isAuthority));
  signed.certificates = [leaf, ...authorities];

  const result = await signed.verify({
    signer: 0,
    data: hexDecode(receipt.digest).slice().buffer,
    trustedCerts: roots,
    checkDate: genTime,
    checkChain: true,
    extendedMode: true,
  });
  if (result.signatureVerified !== true || result.signerCertificateVerified !== true) return false;
  if (!result.signerCertificate || der(result.signerCertificate) !== der(leaf)) return false;
  const path = result.certificatePath;
  const top = path[path.length - 1];
  if (!top || !rootDer.has(der(top))) return false;
  return true;
}

/** More certificates than any real token plus its published chain carry. */
const MAX_CERTIFICATES = 16;

/**
 * The authorities among `offered` whose signatures lead back to one of `roots`, directly or
 * through another accepted one. Everything else is dropped before path building: a self-issued
 * authority under any spelling of its name, a pair that issued each other, and a cross-signed
 * copy of a trust root (DigiCert ships one inside its tokens) that would lead the path away from
 * the trusted self-signed copy.
 */
async function issuedUnder(
  roots: pkijs.Certificate[],
  offered: pkijs.Certificate[],
): Promise<pkijs.Certificate[]> {
  const accepted = [...roots];
  const acceptedDer = new Set(roots.map(der));
  const acceptedKeys = new Set(roots.map(subjectKey));
  let pending = offered.filter((c) => !acceptedDer.has(der(c)) && !acceptedKeys.has(subjectKey(c)));
  const added: pkijs.Certificate[] = [];
  let progress = true;
  while (pending.length > 0 && progress) {
    progress = false;
    for (const certificate of pending) {
      const issuer = accepted.find((a) => a.subject.isEqual(certificate.issuer));
      if (!issuer || !(await signedBy(certificate, issuer))) continue;
      pending = pending.filter((c) => c !== certificate);
      accepted.push(certificate);
      acceptedDer.add(der(certificate));
      added.push(certificate);
      progress = true;
    }
  }
  return added;
}

async function signedBy(
  certificate: pkijs.Certificate,
  issuer: pkijs.Certificate,
): Promise<boolean> {
  try {
    return await certificate.verify(issuer);
  } catch {
    return false;
  }
}

function isAuthority(certificate: pkijs.Certificate): boolean {
  const extension = certificate.extensions?.find((e) => e.extnID === ID_CE_BASIC_CONSTRAINTS);
  const constraints = extension?.parsedValue as pkijs.BasicConstraints | undefined;
  return constraints?.cA === true;
}

function der(certificate: pkijs.Certificate): string {
  return hexEncode(new Uint8Array(certificate.toSchema().toBER()));
}

/**
 * Subject name plus public key. A cross-signed copy of a trust root (DigiCert ships one inside
 * its tokens) shares both with the root and would lead path building away from the trusted
 * self-signed copy, so it is dropped from the candidates.
 */
function subjectKey(certificate: pkijs.Certificate): string {
  const key = hexEncode(new Uint8Array(certificate.subjectPublicKeyInfo.toSchema().toBER()));
  return `${hexEncode(new Uint8Array(certificate.subject.toSchema().toBER()))}:${key}`;
}

function hasTimeStampingUsage(certificate: pkijs.Certificate): boolean {
  const extension = certificate.extensions?.find((e) => e.extnID === ID_CE_EXT_KEY_USAGE);
  if (!extension || !extension.critical) return false;
  const usage = extension.parsedValue as pkijs.ExtKeyUsage | undefined;
  return usage?.keyPurposes.includes(ID_KP_TIME_STAMPING) ?? false;
}

function base64Decode(text: string): ArrayBuffer {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function pemDecode(pem: string): ArrayBuffer {
  const body = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g, "");
  return base64Decode(body);
}
