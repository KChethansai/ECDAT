import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, api, apiFetch } from "../src/lib/api.js";
import { isBackendRouteMiss } from "../src/lib/report.js";

test("isBackendRouteMiss only flags FastAPI unknown-path 404s", () => {
  assert.equal(isBackendRouteMiss(404, '{"detail":"Not Found"}'), true);
  assert.equal(isBackendRouteMiss(404, '{"detail":"unknown report (reports are in-memory; re-POST /scans)"}'), false);
  assert.equal(isBackendRouteMiss(404, "Not Found"), false);
  assert.equal(isBackendRouteMiss(404, ""), false);
  assert.equal(isBackendRouteMiss(400, '{"detail":"Not Found"}'), false);
  assert.equal(isBackendRouteMiss(500, '{"detail":"Not Found"}'), false);
});

test("apiFetch surfaces route-miss 404s as wiring errors, not generic 404s", async () => {
  const real = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response('{"detail":"Not Found"}', { status: 404 });
    await assert.rejects(apiFetch("/plans/verify", { method: "POST", body: {} }), (err) => {
      assert.ok(err instanceof ApiError);
      assert.match(err.message, /Backend route not reachable: \/plans\/verify/);
      return true;
    });
    globalThis.fetch = async () => new Response('{"detail":"unknown report (re-POST /scans)"}', { status: 404 });
    await assert.rejects(apiFetch("/reports/deadbeef"), (err) => {
      assert.ok(err instanceof ApiError);
      assert.match(err.message, /^Not found: unknown report/);
      return true;
    });
  } finally {
    globalThis.fetch = real;
  }
});

test("api methods hit the backend paths+methods from the route inventory", async () => {
  const real = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (path, init = {}) => {
      calls.push({ path, method: init.method || "GET", body: init.body ? JSON.parse(init.body) : undefined });
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    };
    await api.health();
    await api.createScan({ target: "sample" });
    await api.getReport("abc");
    await api.getSarif("a/b");
    await api.scanHistory();
    await api.scanDelta("before-id", "after-id");
    await api.saveTriage("local:t", "fp1", "reviewed", "");
    await api.listTriage("");
    await api.listTriage("local:t");
    await api.createValidation({ report_id: "r" });
    await api.getValidation("v1");
    await api.createCodeAnalysis({ target: "sample" });
    await api.getCodeAnalysis("ca1");
    await api.createPlan({ analysis_id: "ca1", finding_id: "f", option_id: "o" });
    await api.getPlan("p1");
    await api.verifyPlan({ before: [], after: [] });
    const byPath = Object.fromEntries(calls.map((c) => [c.path, c]));
    assert.equal(byPath["/health"].method, "GET");
    assert.equal(byPath["/scans"].method, "POST");
    assert.equal(byPath["/reports/abc"].method, "GET");
    assert.equal(byPath["/reports/a%2Fb/sarif"].method, "GET");
    assert.equal(byPath["/scan-history"].method, "GET");
    assert.deepEqual(byPath["/scan-delta"].body, { before: "before-id", after: "after-id" });
    assert.deepEqual(calls.find((c) => c.path === "/triage" && c.method === "POST").body,
      { scope: "local:t", fingerprint: "fp1", status: "reviewed", reason: "" });
    assert.equal(byPath["/triage?scope=local%3At"].method, "GET");
    assert.equal(byPath["/validations"].method, "POST");
    assert.equal(byPath["/validations/v1"].method, "GET");
    assert.equal(byPath["/code-analysis"].method, "POST");
    assert.equal(byPath["/code-analysis/ca1"].method, "GET");
    assert.equal(byPath["/plans"].method, "POST");
    assert.equal(byPath["/plans/p1"].method, "GET");
    assert.equal(byPath["/plans/verify"].method, "POST");
  } finally {
    globalThis.fetch = real;
  }
});
