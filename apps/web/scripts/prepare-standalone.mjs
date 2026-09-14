import { cpSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const standaloneAppRoot = path.join(appRoot, ".next", "standalone", "apps", "web");

mkdirSync(path.join(standaloneAppRoot, ".next"), { recursive: true });
cpSync(path.join(appRoot, "public"), path.join(standaloneAppRoot, "public"), {
  recursive: true,
  force: true,
});
cpSync(path.join(appRoot, ".next", "static"), path.join(standaloneAppRoot, ".next", "static"), {
  recursive: true,
  force: true,
});

