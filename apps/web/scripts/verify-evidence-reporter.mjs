import fs from "node:fs";
import path from "node:path";

function normalizedRelativeFile(repositoryRoot, file) {
  const relative = path.relative(repositoryRoot, file).replaceAll(path.sep, "/");
  if (!relative || relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error("Playwright reported a test outside the repository root");
  }
  return relative;
}

function writeJsonAtomic(outputFile, value) {
  const directory = path.dirname(outputFile);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = path.join(directory, `.${path.basename(outputFile)}.${process.pid}.${Date.now()}.tmp`);
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  fs.renameSync(temporary, outputFile);
}

export default class VerifyEvidenceReporter {
  constructor(options = {}) {
    this.outputFile = options.outputFile;
    this.repositoryRoot = options.repositoryRoot;
    this.startedAt = new Date().toISOString();
    this.projects = [];
    this.plannedTestCount = 0;
    this.resultsById = new Map();
  }

  onBegin(config, suite) {
    if (!path.isAbsolute(this.outputFile ?? "") || !path.isAbsolute(this.repositoryRoot ?? "")) {
      throw new Error("Verification reporter requires absolute outputFile and repositoryRoot options");
    }
    this.projects = config.projects.map((project) => project.name).sort();
    this.plannedTestCount = suite.allTests().length;
    if (!Number.isInteger(this.plannedTestCount) || this.plannedTestCount < 1) {
      throw new Error("Verification reporter received an empty Playwright plan");
    }
  }

  onTestEnd(test, result) {
    const project = test.parent.project()?.name;
    if (!project) throw new Error("Playwright test result has no project");
    const skip = [...test.annotations].reverse().find((annotation) => annotation.type === "skip");
    this.resultsById.set(test.id, {
      project,
      file: normalizedRelativeFile(this.repositoryRoot, test.location.file),
      line: test.location.line,
      title: test.title,
      status: result.status,
      durationMs: result.duration,
      skipReason: result.status === "skipped" ? (skip?.description ?? null) : null,
    });
  }

  onEnd(result) {
    const results = [...this.resultsById.values()];
    const counts = {
      total: results.length,
      passed: results.filter((entry) => entry.status === "passed").length,
      failed: results.filter((entry) => entry.status === "failed").length,
      skipped: results.filter((entry) => entry.status === "skipped").length,
      timedOut: results.filter((entry) => entry.status === "timedOut").length,
      interrupted: results.filter((entry) => entry.status === "interrupted").length,
    };
    writeJsonAtomic(this.outputFile, {
      schemaVersion: 1,
      startedAtUtc: this.startedAt,
      completedAtUtc: new Date().toISOString(),
      status: result.status,
      projects: this.projects,
      plannedTestCount: this.plannedTestCount,
      counts,
      results: results.sort((left, right) =>
        left.project.localeCompare(right.project)
        || left.file.localeCompare(right.file)
        || left.line - right.line
        || left.title.localeCompare(right.title)),
    });
  }
}
