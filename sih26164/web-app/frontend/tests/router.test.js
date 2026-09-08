import test from "node:test";
import assert from "node:assert/strict";
import { href, parseHash } from "../src/lib/router.js";
import { formatScanError } from "../src/lib/report.js";

test("parseHash routes known sections, falls back to dashboard", () => {
  assert.deepEqual(parseHash("#/findings/abc"), { name: "findings", param: "abc" });
  assert.deepEqual(parseHash("#/scan"), { name: "scan", param: "" });
  assert.deepEqual(parseHash(""), { name: "dashboard", param: "" });
  assert.deepEqual(parseHash("#/nope"), { name: "dashboard", param: "" });
  assert.deepEqual(parseHash("#/reports/a%2Fb"), { name: "reports", param: "a/b" });
});

test("href round-trips through parseHash", () => {
  assert.equal(parseHash(href("history")).name, "history");
  assert.deepEqual(parseHash(href("findings", "x/y")), { name: "findings", param: "x/y" });
});

test("formatScanError maps statuses and FastAPI shapes", () => {
  assert.match(formatScanError(400, "bad target"), /Invalid request: bad target/);
  assert.match(formatScanError(404, '{"detail":"gone"}'), /Not found: gone/);
  assert.match(
    formatScanError(422, '{"detail":[{"loc":["body","target"],"msg":"bad"}]}'),
    /Validation error: target: bad/,
  );
  assert.equal(formatScanError(500, ""), "Scan failed (500)");
});
