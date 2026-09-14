import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { extractZipEntries, inspectTextContent, runSelfTest, scanWorkspace } from "./scan-secrets.mjs";

const projectRoot = path.resolve(import.meta.dirname, "..");
const webRequire = createRequire(path.join(projectRoot, "apps/web/package.json"));

function pinnedExcelJsPublicContacts() {
  const excelJsEntry = webRequire.resolve("exceljs");
  const bundle = fs.readFileSync(path.join(path.dirname(excelJsEntry), "dist/exceljs.min.js"), "utf8");
  const fingerprints = new Set([
    "3de132cd98be7bf26b6f08e81c31c799a891bc32046b61f0b6fe3671ca2e44b5",
    "41bdb9a15c1ff55374e8af8ef433882779105f437d21f143e0c9b5939544d860",
  ]);
  return [...bundle.matchAll(/\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,63}\b/gi)]
    .map(([value]) => value)
    .filter((value) => fingerprints.has(createHash("sha256").update(value.toLowerCase()).digest("hex")));
}

function createStoredZip(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const [name, value] of entries) {
    const nameBuffer = Buffer.from(name, "utf8");
    const content = Buffer.from(value);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt32LE(localOffset, 42);
    localParts.push(local, nameBuffer, content);
    centralParts.push(central, nameBuffer);
    localOffset += local.length + nameBuffer.length + content.length;
  }
  const centralDirectory = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, centralDirectory, eocd]);
}

function writeJson(filename, value) {
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, `${JSON.stringify(value)}\n`, "utf8");
}

function createDeliveryWorkspace() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nom-delivery-scan-"));
  for (const packagePath of ["apps/api", "apps/web", "packages/domain"]) {
    writeJson(path.join(root, packagePath, "package.json"), { scripts: { build: "placeholder" } });
  }
  fs.mkdirSync(path.join(root, "apps/api/dist"), { recursive: true });
  fs.writeFileSync(path.join(root, "apps/api/dist/main.js"), "export const ready = true;\n");
  fs.mkdirSync(path.join(root, "apps/web/.next/standalone/apps/web"), { recursive: true });
  fs.writeFileSync(path.join(root, "apps/web/.next/standalone/apps/web/server.js"), "export const ready = true;\n");
  fs.mkdirSync(path.join(root, "packages/domain/dist"), { recursive: true });
  fs.writeFileSync(path.join(root, "packages/domain/dist/index.js"), "export const ready = true;\n");
  fs.mkdirSync(path.join(root, "docs/evidence"), { recursive: true });
  fs.writeFileSync(path.join(root, "docs/evidence/report.csv"), "name,email\nSynthetic,person@example.invalid\n");
  fs.mkdirSync(path.join(root, "artifacts"), { recursive: true });
  fs.writeFileSync(path.join(root, "artifacts/README.md"), "# Safe evidence\n");
  fs.mkdirSync(path.join(root, "apps/web/.next/standalone/node_modules/vendor"), { recursive: true });
  fs.writeFileSync(path.join(root, "apps/web/.next/standalone/node_modules/vendor/credentials.json"), "not scanned");
  fs.mkdirSync(path.join(root, ".local"), { recursive: true });
  fs.writeFileSync(path.join(root, ".local/private.key"), "must never be read");
  return root;
}

test("self-test covers the high-confidence signatures without exposing matched values", () => {
  assert.doesNotThrow(() => runSelfTest());
  const secret = "gh" + "p_" + "A".repeat(40);
  const findings = inspectTextContent(`prefix ${secret} suffix`, "output.js", { rootLabel: "web-standalone" });
  assert.deepEqual(findings, [{ file: "output.js", line: 1, kind: "GitHub token" }]);
  assert.doesNotMatch(JSON.stringify(findings), new RegExp(secret, "u"));
});

test("evidence PII rules accept reserved synthetic domains and flag high-confidence real patterns", () => {
  const safe = inspectTextContent("person@example.invalid\nadmin@nombramientos.local", "docs/evidence/safe.csv", { rootLabel: "evidence" });
  assert.deepEqual(safe, []);
  const suspiciousEmail = "person" + "@private-company.example.es";
  const suspicious = inspectTextContent(`${suspiciousEmail}\n001-1234567-8\n4111 1111 1111 1111`, "docs/evidence/unsafe.csv", { rootLabel: "evidence" });
  assert.deepEqual(suspicious.map(({ kind }) => kind).sort(), [
    "national identity number pattern",
    "non-reserved email address",
    "payment card number pattern",
  ]);
  assert.equal(JSON.stringify(suspicious).includes(suspiciousEmail), false);
  assert.equal(JSON.stringify(suspicious).includes("4111"), false);
});

test("PII rules run for workspace source, artifacts, dist, standalone, and evidence roots", async () => {
  const root = createDeliveryWorkspace();
  const suspiciousEmail = "person" + "@private-company.example.es";
  try {
    const sourceFile = path.join(root, "README.md");
    fs.writeFileSync(sourceFile, `source=${suspiciousEmail}\n`);
    const publicMaintainerContact = "i" + "@izs.me";
    fs.writeFileSync(path.join(root, "pnpm-lock.yaml"), `public-contact=${publicMaintainerContact}\n`);
    const source = await scanWorkspace(root, "source");
    assert.equal(source.pass, false);
    assert.deepEqual(source.findings.filter(({ kind }) => kind === "non-reserved email address").map(({ file }) => file), ["README.md"]);
    assert.equal(source.piiPolicy.explicitAllowlistMatchCount, 1);
    const lockAllowlist = source.piiPolicy.explicitAllowlist.find(({ id }) => id === "PNPM_LOCK_PUBLIC_GLOB_MAINTAINER_CONTACT");
    assert.deepEqual({ pathScope: lockAllowlist?.pathScope, matchedCount: lockAllowlist?.matchedCount }, {
      pathScope: "pnpm-lock.yaml",
      matchedCount: 1,
    });
    assert.equal(JSON.stringify(source.piiPolicy).includes(publicMaintainerContact), false);

    const deliveryFiles = [
      "apps/api/dist/pii.js",
      "apps/web/.next/standalone/apps/web/pii.js",
      "artifacts/pii.json",
      "docs/evidence/pii.csv",
    ];
    for (const relative of deliveryFiles) fs.writeFileSync(path.join(root, relative), `value=${suspiciousEmail}\n`);
    const delivery = await scanWorkspace(root, "delivery");
    assert.equal(delivery.pass, false);
    assert.deepEqual(
      delivery.findings.filter(({ kind }) => kind === "non-reserved email address").map(({ file }) => file).sort(),
      deliveryFiles.sort(),
    );
    assert.equal(delivery.piiPolicy.evaluatedMatchCount >= deliveryFiles.length, true);
    assert.equal(JSON.stringify(delivery.findings).includes(suspiciousEmail), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("ZIP reader returns bounded entry content and rejects traversal", () => {
  const archive = createStoredZip([["safe/report.txt", "synthetic"]]);
  const entries = extractZipEntries(archive);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, "safe/report.txt");
  assert.equal(entries[0].content.toString("utf8"), "synthetic");
  const traversal = createStoredZip([["../private.key", "hidden"]]);
  assert.throws(() => extractZipEntries(traversal), /Unsafe ZIP path/u);
});

test("delivery scan requires every build root, excludes dependencies, and scans evidence archives", async () => {
  const root = createDeliveryWorkspace();
  try {
    const workbook = createStoredZip([
      ["[Content_Types].xml", "<Types/>"] ,
      ["_rels/.rels", "<Relationships/>"] ,
      ["xl/workbook.xml", "<workbook/>"] ,
      ["xl/sharedStrings.xml", "<sst><si><t>synthetic@example.invalid</t></si></sst>"],
    ]);
    fs.writeFileSync(path.join(root, "docs/evidence/report.xlsx"), workbook);
    const vendorContacts = pinnedExcelJsPublicContacts();
    assert.equal(vendorContacts.length, 2);
    const bundledVendorDirectory = path.join(root, "apps/web/.next/standalone/apps/web/.next/static/chunks");
    fs.mkdirSync(bundledVendorDirectory, { recursive: true });
    fs.writeFileSync(path.join(bundledVendorDirectory, "vendor.js"), vendorContacts.join("\n"));
    const first = await scanWorkspace(root, "delivery");
    assert.equal(first.pass, true);
    assert.equal(first.roots.filter(({ required }) => required).every(({ present }) => present), true);
    assert.equal(first.archiveEntryCount, 4);
    assert.equal(first.exclusions.localSecretDirectoriesRead, 0);
    assert.ok(first.exclusions.dependencyCacheOrRuntimeDirectoryCount >= 1);
    assert.equal(first.piiPolicy.explicitAllowlist
      .filter(({ id }) => id.startsWith("EXCELJS_PUBLIC_CONTACT_"))
      .reduce((total, { matchedCount }) => total + matchedCount, 0), 2);

    const token = "glpat-" + "B".repeat(24);
    fs.writeFileSync(path.join(root, "apps/api/dist/credentials.json"), token);
    const unsafe = await scanWorkspace(root, "delivery");
    assert.equal(unsafe.pass, false);
    assert.equal(unsafe.findings.some(({ kind }) => kind === "forbidden credential or secret-store filename"), true);
    assert.equal(unsafe.findings.some(({ kind }) => kind === "GitLab token"), true);
    assert.equal(JSON.stringify(unsafe.findings).includes(token), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("source scope never descends into local runtime-secret, generated, dependency, or evidence directories", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nom-source-scan-"));
  try {
    fs.writeFileSync(path.join(root, "README.md"), "safe\n");
    const excluded = [".local", ".local-quarantine", "node_modules", "dist", "artifacts", "docs/evidence"];
    const token = "AKIA" + "C".repeat(16);
    for (const directory of excluded) {
      fs.mkdirSync(path.join(root, directory), { recursive: true });
      fs.writeFileSync(path.join(root, directory, "secret.txt"), token);
    }
    const report = await scanWorkspace(root, "source");
    assert.equal(report.pass, true);
    assert.equal(report.fileCount, 1);
    assert.equal(report.exclusions.localSecretDirectoriesRead, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
