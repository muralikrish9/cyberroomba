import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

import { normalizeRecon } from "./normalize.js";

const fixtureDir = resolve(process.cwd(), "config/mock-recon");

function loadJson(name: string) {
  const file = resolve(fixtureDir, name);
  return JSON.parse(readFileSync(file, "utf-8"));
}

const subfinder = loadJson("subfinder.json");
const amass = loadJson("amass.json");
const httpx = loadJson("httpx.json");
const securitytrails = loadJson("securitytrails.json");

const results = normalizeRecon({
  jobId: "job-fixture",
  targetId: "target-fixture",
  primaryTarget: "spacey.com",
  subfinder,
  amass,
  httpx,
  securitytrails,
});

assert.ok(results.length >= 3, "Expected at least three recon results");
assert.ok(results.every((r) => r.sources[0]?.runId === "job-fixture"), "Run ID should propagate");
assert.ok(results.some((r) => r.isAlive), "At least one host should be marked alive");

console.log(`Recon fixture normalization passed (${results.length} hosts)`);
