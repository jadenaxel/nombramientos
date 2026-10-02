import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_CANONICAL_API_ORIGIN = "http://localhost:4000";
const FORBIDDEN_BROWSER_API_ORIGINS = Object.freeze([
  "http://127.0.0.1:4000",
  "http://[::1]:4000",
]);

export function assertCanonicalBrowserOriginBundle(directory, options = {}) {
  const result = inspectBrowserOriginBundle(directory, options);
  if (result.chunkCount === 0) {
    throw new Error("The Next.js browser bundle contains no JavaScript chunks to inspect");
  }
  if (result.forbiddenFiles.length > 0) {
    throw new Error(`The browser bundle contains a non-canonical API origin in: ${result.forbiddenFiles.join(", ")}`);
  }
  if (!result.canonicalOriginPresent) {
    throw new Error("The browser bundle does not contain the canonical localhost API origin");
  }
  return result;
}

export function inspectBrowserOriginBundle(directory, options = {}) {
  const root = path.resolve(directory);
  const requiredOrigin = options.requiredOrigin ?? REQUIRED_CANONICAL_API_ORIGIN;
  const forbiddenOrigins = options.forbiddenOrigins ?? FORBIDDEN_BROWSER_API_ORIGINS;
  const chunks = javascriptFiles(root);
  const forbiddenFiles = [];
  let canonicalOriginPresent = false;

  for (const file of chunks) {
    const content = readFileSync(file, "utf8");
    if (content.includes(requiredOrigin)) canonicalOriginPresent = true;
    if (forbiddenOrigins.some((origin) => content.includes(origin))) {
      forbiddenFiles.push(path.relative(root, file).split(path.sep).join("/"));
    }
  }

  return Object.freeze({
    chunkCount: chunks.length,
    canonicalOriginPresent,
    forbiddenFiles: Object.freeze(forbiddenFiles),
  });
}

function javascriptFiles(directory) {
  const files = [];
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(candidate);
      else if (entry.isFile() && entry.name.endsWith(".js")) files.push(candidate);
    }
  }
  return files.sort();
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const integrated = process.env.GESTIONCHURCH_MODULE_MODE === "true";
  const result = assertCanonicalBrowserOriginBundle(path.join(appRoot, ".next", "static", "chunks"), integrated ? {
    requiredOrigin: "http://localhost:4100",
    forbiddenOrigins: ["http://127.0.0.1:4100", "http://[::1]:4100"],
  } : {});
  process.stdout.write(`${JSON.stringify({ status: "passed", chunksInspected: result.chunkCount })}\n`);
}
