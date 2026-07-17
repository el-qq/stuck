import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const jsonFiles = ["package.json", "package-lock.json", "frontend/package.json", "frontend/package-lock.json"];
const backendFile = "backend/app/__init__.py";

async function readJson(relative) {
  return JSON.parse(await readFile(resolve(root, relative), "utf8"));
}

async function setVersion(version) {
  for (const relative of jsonFiles) {
    const data = await readJson(relative);
    data.version = version;
    if (data.packages?.[""]) data.packages[""].version = version;
    await writeFile(resolve(root, relative), `${JSON.stringify(data, null, 2)}\n`);
  }

  const path = resolve(root, backendFile);
  const source = await readFile(path, "utf8");
  if (!/^__version__ = "[^"]+"$/m.test(source)) {
    throw new Error(`${backendFile}: __version__ not found`);
  }
  await writeFile(path, source.replace(/^__version__ = "[^"]+"$/m, `__version__ = "${version}"`));
}

async function versions() {
  const result = [];
  for (const relative of jsonFiles) {
    const data = await readJson(relative);
    result.push([relative, data.version]);
    if (data.packages?.[""]) result.push([`${relative}#packages[\"\"]`, data.packages[""].version]);
  }
  const backend = await readFile(resolve(root, backendFile), "utf8");
  const match = /^__version__ = "([^"]+)"$/m.exec(backend);
  result.push([backendFile, match?.[1]]);
  return result;
}

const setIndex = process.argv.indexOf("--set");
if (setIndex >= 0) {
  const requested = process.argv[setIndex + 1];
  if (!requested || !semver.test(requested)) {
    throw new Error("Usage: npm run version:set -- <semver>, for example 0.2.0");
  }
  await setVersion(requested);
}

const found = await versions();
const expected = found[0]?.[1];
const mismatches = found.filter(([, version]) => version !== expected || !version || !semver.test(version));
if (mismatches.length > 0) {
  for (const [file, version] of found) process.stderr.write(`${file}: ${version ?? "missing"}\n`);
  throw new Error("Application versions are not synchronized");
}
process.stdout.write(`STUCK version ${expected}\n`);
