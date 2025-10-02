import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

import { parseNucleiResults, parseNmapVulnerabilities, mergeFindings } from "./parse.js";
import { CveMatcher } from "./matcher.js";

const fixtureDir = resolve(process.cwd(), "config/mock-vuln");

function load(name: string) {
  return JSON.parse(readFileSync(resolve(fixtureDir, name), "utf-8"));
}

const nucleiRaw = load("nuclei.json");
const nmapRaw = load("nmap.json");
const nvdRaw = load("nvd.json");

const nucleiFindings = parseNucleiResults({ reconId: "recon-1", jobId: "job-1", raw: nucleiRaw });
const nmapFindings = parseNmapVulnerabilities({ reconId: "recon-1", jobId: "job-1", raw: nmapRaw });

const combined = mergeFindings(nucleiFindings, nmapFindings);
assert.equal(combined.length, 3, "Expected 3 findings (2 nuclei + 1 nmap)");

const feed = CveMatcher.parseNvdFeed(nvdRaw);
const index = CveMatcher.buildCveIndex(feed);
const enriched = CveMatcher.enrichVulnerabilitiesWithNvd(combined, index);

const critical = enriched.find((f) => f.title.includes("Example RCE"));
assert.ok(critical && critical.cves?.[0]?.cvss?.baseScore === 9.8, "Critical finding should have CVSS 9.8");

const nmapCve = enriched.find((f) => f.source === "nmap");
assert.ok(nmapCve && nmapCve.cves?.[0]?.cvss?.baseScore === 7.0, "Nmap CVE should be enriched");

const techSuggestions = CveMatcher.suggestCvesFromTech(
  [
    { name: "SpaceY Portal", version: "2.3" },
    { name: "OpenSSH", version: "8.4" },
  ],
  index,
);
assert.ok(techSuggestions.length >= 2, "Should suggest CVEs for known tech");

console.log(`Vulnerability fixture checks passed (findings=${enriched.length}, suggestions=${techSuggestions.length})`);
