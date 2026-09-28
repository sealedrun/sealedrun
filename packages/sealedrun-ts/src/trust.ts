import shipped from "./witnesses.json" with { type: "json" };

/**
 * One entry of the witness trust list (SPEC 8.4): a witness endpoint and what its receipts are
 * checked against. The package ships a list built from the Sigstore trust root and DigiCert's
 * published roots; callers may pass their own or extend it. Certificates carried in a receipt
 * are never trusted on their own.
 */
export interface Witness {
  /** `rfc3161` or `rekor`. */
  type: string;
  /** Endpoint URL as written in the anchor record's `witness`. */
  uri: string;
  /** Human-readable name of the trust root. */
  subject: string;
  /** Receipts timed before `start` or after `end` (when set) are not accepted. */
  validFor: { start: Date; end?: Date };
  /** PEM root certificates (`rfc3161`). */
  roots: string[];
  /** PEM public key of the log (`rekor`). */
  publicKey?: string;
  /** Hex SHA-256 of the log's DER public key (`rekor`). */
  logId?: string;
}

/** `witnesses.json` entry as written. */
export interface WitnessJson {
  type: string;
  uri: string;
  subject: string;
  valid_for: { start: string; end?: string };
  roots?: string[];
  public_key?: string;
  log_id?: string;
}

/** Turns a `witnesses.json` entry into a {@link Witness}. */
export function witnessFromJson(entry: WitnessJson): Witness {
  const witness: Witness = {
    type: entry.type,
    uri: entry.uri,
    subject: entry.subject,
    validFor: { start: parseInstant(entry.valid_for.start) },
    roots: entry.roots ?? [],
  };
  if (entry.valid_for.end !== undefined) witness.validFor.end = parseInstant(entry.valid_for.end);
  if (entry.public_key !== undefined) witness.publicKey = entry.public_key;
  if (entry.log_id !== undefined) witness.logId = entry.log_id;
  return witness;
}

/** The trust list shipped with the package. */
export function shippedWitnesses(): Witness[] {
  return (shipped.witnesses as WitnessJson[]).map(witnessFromJson);
}

/** Entries matching an anchor's `type` and `witness` URL, or `logId` for `rekor`. */
export function selectWitnesses(
  witnesses: Witness[],
  type: string,
  uri: string,
  logId?: string,
): Witness[] {
  return witnesses.filter(
    (w) => w.type === type && (w.uri === uri || (logId !== undefined && w.logId === logId)),
  );
}

/** True when `moment` lies within the entry's validity. */
export function witnessCovers(witness: Witness, moment: Date): boolean {
  const { start, end } = witness.validFor;
  return (
    start.getTime() <= moment.getTime() && (end === undefined || moment.getTime() <= end.getTime())
  );
}

/**
 * Parses an RFC 3339 instant in any precision.
 *
 * @throws TypeError if the text is not a date.
 */
export function parseInstant(text: string): Date {
  const value = Date.parse(text);
  if (Number.isNaN(value)) throw new TypeError(`invalid instant ${text}`);
  return new Date(value);
}
