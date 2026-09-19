const PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function parseTimestamp(text: string): number {
  if (!PATTERN.test(text)) throw new TypeError(`invalid timestamp ${text}`);
  const value = Date.parse(text);
  if (Number.isNaN(value)) throw new TypeError(`invalid timestamp ${text}`);
  return value;
}
