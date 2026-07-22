import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

const exception = {
  advisoryUrl: "https://github.com/advisories/GHSA-395f-4hp3-45gv",
  parentPackage: "concurrently",
  parentVersion: "10.0.3",
  vulnerablePackage: "shell-quote",
};

const audit = spawnSync(npm, ["audit", "--audit-level=high", "--json"], {
  cwd: root,
  encoding: "utf8",
});

if (audit.error) {
  throw audit.error;
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch {
  process.stdout.write(audit.stdout);
  process.stderr.write(audit.stderr);
  process.exit(audit.status ?? 1);
}

const vulnerabilities = report.vulnerabilities ?? {};
const shellQuote = vulnerabilities[exception.vulnerablePackage];
const concurrently = vulnerabilities[exception.parentPackage];
const shellQuoteAdvisory = shellQuote?.via?.find((entry) => typeof entry === "object" && entry.url === exception.advisoryUrl);
const accepted =
  packageJson.devDependencies?.[exception.parentPackage] === exception.parentVersion &&
  shellQuote?.severity === "high" &&
  shellQuoteAdvisory &&
  concurrently?.isDirect === true &&
  concurrently.via?.length === 1 &&
  concurrently.via[0] === exception.vulnerablePackage;

const ignored = accepted ? new Set([exception.parentPackage, exception.vulnerablePackage]) : new Set();
const remaining = Object.entries(vulnerabilities).filter(
  ([name, finding]) => !ignored.has(name) && (finding.severity === "high" || finding.severity === "critical"),
);

if (remaining.length > 0 || !accepted) {
  process.stdout.write(audit.stdout);
  process.stderr.write(audit.stderr);
  process.exit(audit.status ?? 1);
}

// Reviewed exception: `concurrently@10.0.3` is a root dev-only launcher used
// with fixed commands. It imports `shell-quote.quote`, while GHSA-395f-4hp3-45gv
// affects only `shell-quote.parse`. Revoke and review this exception whenever
// concurrently is updated.
console.log(`Accepted dev-only npm audit exception: ${exception.vulnerablePackage} via ${exception.parentPackage} (${exception.advisoryUrl}).`);
