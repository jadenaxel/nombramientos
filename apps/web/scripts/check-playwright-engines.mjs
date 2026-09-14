import { chromium, firefox, webkit } from "@playwright/test";
import {
  classifyEngineLaunchError,
  engineLaunchErrorLine,
} from "./playwright-engine-diagnostics.mjs";

const engines = [
  ["chromium", chromium, true],
  ["firefox", firefox, false],
  ["webkit", webkit, true],
];

const results = [];
for (const [name, engine, required] of engines) {
  const startedAt = Date.now();
  try {
    const browser = await engine.launch({ headless: true, timeout: 15_000 });
    await browser.close();
    results.push({ name, required, available: true, elapsedMs: Date.now() - startedAt });
  } catch (error) {
    results.push({
      name,
      required,
      available: false,
      elapsedMs: Date.now() - startedAt,
      code: classifyEngineLaunchError(error),
      error: engineLaunchErrorLine(error),
    });
  }
}

process.stdout.write(`${JSON.stringify({ schemaVersion: 1, results })}\n`);

if (results.some((result) => result.required && !result.available)) {
  process.exitCode = 1;
} else if (results.some((result) => result.name === "firefox" && !result.available)) {
  // A distinct code lets the Windows verification wrapper record an explicit
  // native-engine limitation while still exercising the required matrix.
  process.exitCode = 2;
}
