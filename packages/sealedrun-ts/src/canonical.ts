export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function canonicalize(value: Json): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite numbers are not allowed");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const keys = Object.keys(value).sort(compareUtf16);
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key] as Json)}`);
  return `{${parts.join(",")}}`;
}

export function canonicalBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
