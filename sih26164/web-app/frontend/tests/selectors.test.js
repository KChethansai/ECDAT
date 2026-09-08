import test from "node:test";
import assert from "node:assert/strict";
import {
  activeFilterLabels, algorithmFamilies, canonicalFamily, codeStats,
  criticalHighCount, filterFindings, findingById, quantumExposure,
  repoIdentity, scannerSources, severityCounts,
} from "../src/lib/selectors.js";

const report = {
  components: [
    { id: "a", severity: "critical", priority: "P0", scanner: "source", algorithm: "RSA-2048", library: "openssl", file_path: "a.py", evidence: "e", usage: "sign" },
    { id: "b", severity: "high", priority: "P1", scanner: "binary", algorithm: "AES-128", file_path: "b.bin", evidence: "e", usage: "encrypt" },
    { id: "c", severity: "weird", priority: "P9", scanner: "source", algorithm: "?", file_path: "c.py", evidence: "e", usage: "x" },
  ],
  summary: { total: 3, bySeverity: { critical: 1, high: 1, medium: 0, low: 0 } },
  source: { type: "github", owner: "o", repo: "r", ref_requested: "main", sha: "abc", profile: "full" },
  codeAnalysis: { analysis_id: "ca1", findings: [{ id: "cf1", category: "DEAD_CODE" }, { id: "cf2", category: "DEAD_CODE" }] },
};

test("severityCounts prefers backend tally, ignores unknown tiers", () => {
  assert.deepEqual(severityCounts(report), { critical: 1, high: 1, medium: 0, low: 0 });
  assert.equal(criticalHighCount(report), 2);
});

test("scannerSources falls back to component scanners", () => {
  assert.deepEqual(scannerSources(report), ["source", "binary"]);
  assert.deepEqual(scannerSources({ metadata: { scannerSources: ["source"] } }), ["source"]);
});

test("filterFindings combines priority, severity, scanner, query", () => {
  const all = report.components;
  assert.equal(filterFindings(all, {}).length, 3);
  assert.equal(filterFindings(all, { priority: "P0" }).length, 1);
  assert.equal(filterFindings(all, { severity: "critical" }).length, 1);
  assert.equal(filterFindings(all, { scanner: "binary" }).length, 1);
  assert.equal(filterFindings(all, { query: "openssl" }).length, 1);
  assert.equal(filterFindings(all, { query: "zzz" }).length, 0);
  assert.deepEqual(activeFilterLabels({}), []);
  assert.deepEqual(activeFilterLabels({ severity: "high", query: "x" }), ["severity high", "“x”"]);
});

test("repoIdentity null for local reports", () => {
  assert.equal(repoIdentity({}), null);
  assert.equal(repoIdentity({ source: { type: "local" } }), null);
  assert.equal(repoIdentity(report).sha, "abc");
});

test("algorithmFamilies groups deterministically", () => {
  const fams = algorithmFamilies(report);
  assert.deepEqual(fams.map((g) => g.family), ["AES", "RSA"]); // ties break by name
  assert.ok(fams.every((g) => g.count >= 1));
  assert.equal(quantumExposure(report), 1);
  assert.equal(canonicalFamily("aes-256-gcm"), "AES");
  assert.equal(canonicalFamily("?"), "");
});

test("codeStats buckets categories", () => {
  const stats = codeStats(report.codeAnalysis);
  assert.equal(stats.total, 2);
  assert.deepEqual(stats.byCategory, { DEAD_CODE: 2 });
  assert.equal(stats.analysisId, "ca1");
});

test("findingById returns null when absent", () => {
  assert.equal(findingById(report, "a").severity, "critical");
  assert.equal(findingById(report, "nope"), null);
  assert.equal(findingById(null, "a"), null);
});
