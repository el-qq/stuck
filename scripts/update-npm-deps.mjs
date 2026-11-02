import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

for (const directory of [root, resolve(root, "frontend")]) {
  const manifest = JSON.parse(readFileSync(resolve(directory, "package.json"), "utf8"));
  for (const [section, flag] of [
    ["dependencies", "--save-prod"],
    ["devDependencies", "--save-dev"],
    ["optionalDependencies", "--save-optional"],
  ]) {
    const packages = Object.keys(manifest[section] ?? {}).map((name) => `${name}@latest`);
    if (packages.length === 0) continue;
    const result = spawnSync("npm", ["install", flag, "--save-exact", ...packages], {
      cwd: directory,
      stdio: "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
  // Refresh compatible transitive dependencies in the lock file as well.
  const result = spawnSync("npm", ["update"], { cwd: directory, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
