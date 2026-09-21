const PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * Parses a SPEC 3 timestamp: UTC, millisecond precision, `Z` suffix. Any other RFC 3339 form is
 * rejected so that one instant has one signed spelling.
 *
 * @returns Milliseconds since the Unix epoch.
 * @throws TypeError if the text has another form or names an impossible date.
 */
export function parseTimestamp(text: string): number {
  if (!PATTERN.test(text)) throw new TypeError(`invalid timestamp ${text}`);
  const value = Date.parse(text);
  if (Number.isNaN(value)) throw new TypeError(`invalid timestamp ${text}`);
  return value;
}
