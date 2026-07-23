import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = fileURLToPath(new URL("..", import.meta.url));
const dist = path.join(frontendRoot, "dist");

function normalizedBasePath(value) {
  const trimmed = value?.trim();
  if (!trimmed || trimmed === "/") return "/";
  return `/${trimmed.replace(/^\/+|\/+$/g, "")}/`;
}

async function filesIn(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const entryPath = path.join(directory, entry.name);
      return entry.isDirectory() ? filesIn(entryPath) : [entryPath];
    }),
  );
  return files.flat();
}

function fail(message) {
  throw new Error(`Invalid GitHub Pages demo artifact: ${message}`);
}

const indexPath = path.join(dist, "index.html");
const index = await readFile(indexPath, "utf8");
const basePath = normalizedBasePath(process.env.VITE_BASE_PATH);

if (!index.includes(`src=\"${basePath}assets/`)) fail(`index.html does not reference its JavaScript through base path ${basePath}`);
if (index.includes("/main.tsx") || index.includes("/demo-main.tsx")) fail("index.html still contains a source TypeScript entry");

// The static artifact must stay incapable of contacting a STUCK backend. Scan
// emitted text, not source files: this catches accidental provider imports as
// well as an explicit request added to the demo UI.
for (const file of await filesIn(dist)) {
  if (!/\.(?:html|js|css)$/u.test(file)) continue;
  const contents = await readFile(file, "utf8");
  if (contents.includes("/api/")) fail(`${path.relative(dist, file)} contains an API route`);
}

console.log(`Verified offline demo artifact at ${basePath}`);
