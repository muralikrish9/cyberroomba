import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

import {
  parseBugcrowdScope,
  parseHackerOneScope,
  parseIntigritiScope,
  normalizeAllPlatforms,
} from "./parsers.js";

const fixtureDir = resolve(process.cwd(), "config/mock-scope");

function loadFixture(name: string) {
  const file = resolve(fixtureDir, name);
  const raw = readFileSync(file, "utf-8");
  return JSON.parse(raw);
}

const bugcrowdRaw = loadFixture("bugcrowd.json");
const hackeroneRaw = loadFixture("hackerone.json");
const intigritiRaw = loadFixture("intigriti.json");

const bugcrowdTargets = parseBugcrowdScope(bugcrowdRaw);
assert.equal(bugcrowdTargets.length, 4, "Bugcrowd fixture should produce 4 targets");
assert.ok(bugcrowdTargets.every((t) => t.source === "bugcrowd"), "Bugcrowd targets should be tagged correctly");

const hackeroneTargets = parseHackerOneScope(hackeroneRaw);
assert.equal(hackeroneTargets.length, 4, "HackerOne fixture should produce 4 targets");
assert.ok(hackeroneTargets.every((t) => typeof t.metadata?.assetType === "string"), "HackerOne metadata should preserve asset type");

const intigritiTargets = parseIntigritiScope(intigritiRaw);
assert.equal(intigritiTargets.length, 6, "Intigriti fixture should produce 6 targets");
assert.ok(intigritiTargets.some((t) => t.asset.type === "cidr"), "Intigriti targets should include CIDR entry");

const allTargets = normalizeAllPlatforms({
  bugcrowd: bugcrowdRaw,
  hackerone: hackeroneRaw,
  intigriti: intigritiRaw,
});

assert.equal(allTargets.length, 14, "Combined targets should sum all fixtures");

console.log("Scope fixture validation passed:");
console.log(`  Bugcrowd: ${bugcrowdTargets.length}`);
console.log(`  HackerOne: ${hackeroneTargets.length}`);
console.log(`  Intigriti: ${intigritiTargets.length}`);
