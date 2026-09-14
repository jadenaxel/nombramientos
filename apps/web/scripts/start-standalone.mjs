import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { resolveStandaloneBinding } from "./standalone-boundary.mjs";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binding = resolveStandaloneBinding();
process.env.HOSTNAME = binding.host;
process.env.PORT = binding.port;
process.chdir(path.join(appRoot, ".next", "standalone", "apps", "web"));
await import(pathToFileURL(path.join(process.cwd(), "server.js")).href);
