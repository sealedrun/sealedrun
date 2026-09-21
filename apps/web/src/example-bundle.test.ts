import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

/** The "Try the example bundle" link serves a copy, because the Docker UI stage only sees apps/web. */
test("public/example-bundle.zip is the current spec example", () => {
  const copy = readFileSync(join(__dirname, "..", "public", "example-bundle.zip"));
  const source = readFileSync(join(__dirname, "..", "..", "..", "spec", "examples", "bundle.zip"));
  expect(copy.equals(source)).toBe(true);
});
