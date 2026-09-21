/** Encodes bytes as base64url without padding (RFC 4648 section 5). */
export function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes base64url, with or without padding.
 *
 * @throws DOMException if the text is not valid base64.
 */
export function b64urlDecode(text: string): Uint8Array {
  const padded =
    text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Encodes bytes as lowercase hex. */
export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Decodes lowercase hex. Uppercase digits are rejected because `hash` and `prev_hash` are
 * compared as strings.
 *
 * @throws TypeError if the length is odd or a character is outside `0-9a-f`.
 */
export function hexDecode(text: string): Uint8Array {
  if (text.length % 2 !== 0 || /[^0-9a-f]/.test(text)) throw new TypeError("invalid hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Joins byte arrays into a new array. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
