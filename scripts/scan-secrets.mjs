import { createHash } from "node:crypto";
import { readFile, readdir, rename, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inflateRawSync, inflateSync } from "node:zlib";

const defaultWorkspaceRoot = path.resolve(import.meta.dirname, "..");
const scannerVersion = 2;
const maximumFileBytes = 64 * 1024 * 1024;
const maximumArchiveEntryBytes = 32 * 1024 * 1024;
const maximumArchiveExpandedBytes = 96 * 1024 * 1024;
const maximumArchiveEntries = 10_000;
const sourceExcludedDirectories = new Set([
  ".git", ".local", ".next", ".pnpm-store", "artifacts", "coverage", "dist", "node_modules",
  "playwright-report", "test-results", "tmp",
]);
const deliveryExcludedDirectories = new Set([
  ".git", ".local", ".pnpm-store", "coverage", "node_modules", "playwright-report", "test-results", "tmp",
]);
const sourceExcludedPrefixes = Object.freeze(["docs/evidence"]);
const reportRelativePath = "artifacts/delivery-security-scan.json";
const binaryExtensions = new Set([
  ".avif", ".gif", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".ttf", ".webp", ".woff", ".woff2", ".xlsx", ".zip",
]);
const forbiddenDeliveryExtensions = new Set([
  ".bak", ".cer", ".crt", ".db", ".der", ".dmp", ".dump", ".jks", ".key", ".kdbx", ".keystore",
  ".p12", ".pem", ".pfx", ".pid", ".sqlite", ".sqlite3",
]);
const forbiddenArchiveExtensions = new Set([
  ".bat", ".cmd", ".com", ".dll", ".exe", ".jar", ".js", ".jse", ".key", ".msi", ".p12", ".pem",
  ".pfx", ".ps1", ".scr", ".vbe", ".vbs", ".wsf",
]);
const reservedSyntheticEmailHostnames = Object.freeze(["localhost", "nombramientos.local", "example.com", "example.net", "example.org"]);
const reservedSyntheticEmailSuffixes = Object.freeze([".local", ".invalid", ".test", ".example"]);
const explicitPiiAllowlist = Object.freeze([
  {
    id: "PNPM_LOCK_PUBLIC_GLOB_MAINTAINER_CONTACT",
    file: "pnpm-lock.yaml",
    kind: "email",
    valueSha256: "b0373516d594ddd199b25c3655332b354837e065c5cc232f5043189897900ca7",
    reason: "Public third-party maintainer contact embedded in a dependency deprecation notice.",
  },
  {
    id: "EXCELJS_PUBLIC_CONTACT_1_IN_WEB_BUNDLE",
    filePrefixes: ["apps/web/.next/standalone/apps/web/.next/server/chunks/", "apps/web/.next/standalone/apps/web/.next/static/chunks/"],
    kind: "email",
    valueSha256: "3de132cd98be7bf26b6f08e81c31c799a891bc32046b61f0b6fe3671ca2e44b5",
    reason: "Public third-party contact reproduced byte-for-byte from the pinned exceljs@4.4.0 browser bundle.",
  },
  {
    id: "EXCELJS_PUBLIC_CONTACT_2_IN_WEB_BUNDLE",
    filePrefixes: ["apps/web/.next/standalone/apps/web/.next/server/chunks/", "apps/web/.next/standalone/apps/web/.next/static/chunks/"],
    kind: "email",
    valueSha256: "41bdb9a15c1ff55374e8af8ef433882779105f437d21f143e0c9b5939544d860",
    reason: "Public third-party contact reproduced byte-for-byte from the pinned exceljs@4.4.0 browser bundle.",
  },
]);
const signatures = Object.freeze([
  { name: "private key", pattern: /-----BEGIN ((?:EC |OPENSSH |PGP |RSA )?PRIVATE KEY)-----[\s\S]{64,8192}?-----END \1-----/g },
  { name: "AWS access key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { name: "GitHub token", pattern: /\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{36,255}\b/g },
  { name: "GitLab token", pattern: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g },
  { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "Slack token", pattern: /\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{20,255}\b/g },
  { name: "Stripe live key", pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,255}\b/g },
  { name: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/g },
]);

export async function scanWorkspace(workspaceRoot = defaultWorkspaceRoot, scope = "source") {
  const root = path.resolve(workspaceRoot);
  if (!["source", "delivery", "all"].includes(scope)) throw new Error(`Unsupported scan scope: ${scope}`);
  const requestedScopes = scope === "all" ? ["source", "delivery"] : [scope];
  const findings = [];
  const inventory = [];
  const rootResults = [];
  const counters = {
    textFiles: 0,
    binaryFiles: 0,
    archiveEntries: 0,
    bytes: 0,
    excludedDirectories: 0,
    excludedEphemeralFiles: 0,
    piiMatchesEvaluated: 0,
    piiReservedSyntheticMatches: 0,
    piiExplicitAllowlistMatches: new Map(explicitPiiAllowlist.map(({ id }) => [id, 0])),
  };

  if (requestedScopes.includes("source")) {
    const before = inventory.length;
    await walkDirectory(root, {
      workspaceRoot: root,
      scope: "source",
      rootLabel: "workspace-source",
      findings,
      inventory,
      counters,
    });
    rootResults.push({ label: "workspace-source", path: ".", required: true, present: true, fileCount: inventory.length - before });
  }

  if (requestedScopes.includes("delivery")) {
    const deliveryRoots = await discoverDeliveryRoots(root);
    for (const deliveryRoot of deliveryRoots) {
      const before = inventory.length;
      let entries;
      try {
        entries = await readdir(deliveryRoot.absolutePath, { withFileTypes: true });
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
        rootResults.push({
          label: deliveryRoot.label,
          path: deliveryRoot.relativePath,
          required: deliveryRoot.required,
          present: false,
          fileCount: 0,
        });
        if (deliveryRoot.required) {
          findings.push({ file: deliveryRoot.relativePath, line: null, kind: "required delivery root is missing" });
        }
        continue;
      }
      for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
        await walkEntry(deliveryRoot.absolutePath, entry, {
          workspaceRoot: root,
          scope: "delivery",
          rootLabel: deliveryRoot.label,
          findings,
          inventory,
          counters,
        });
      }
      rootResults.push({
        label: deliveryRoot.label,
        path: deliveryRoot.relativePath,
        required: deliveryRoot.required,
        present: true,
        fileCount: inventory.length - before,
      });
    }
  }

  const orderedInventory = inventory.sort((left, right) => left.path.localeCompare(right.path, "en"));
  const manifestHash = createHash("sha256");
  for (const item of orderedInventory) {
    manifestHash.update(item.path);
    manifestHash.update("\0");
    manifestHash.update(String(item.bytes));
    manifestHash.update("\0");
    manifestHash.update(item.sha256);
    manifestHash.update("\n");
  }
  findings.sort((left, right) => `${left.file}:${left.line ?? 0}:${left.kind}`.localeCompare(`${right.file}:${right.line ?? 0}:${right.kind}`, "en"));

  return {
    schemaVersion: 1,
    scannerVersion,
    scope,
    pass: findings.length === 0,
    fileCount: orderedInventory.length,
    textFileCount: counters.textFiles,
    binaryFileCount: counters.binaryFiles,
    archiveEntryCount: counters.archiveEntries,
    bytesScanned: counters.bytes,
    manifestSha256: manifestHash.digest("hex"),
    roots: rootResults,
    exclusions: {
      dependencyCacheOrRuntimeDirectoryCount: counters.excludedDirectories,
      ephemeralFileCount: counters.excludedEphemeralFiles,
      localSecretDirectoriesRead: 0,
    },
    piiPolicy: {
      evaluatedMatchCount: counters.piiMatchesEvaluated,
      reservedSyntheticMatchCount: counters.piiReservedSyntheticMatches,
      explicitAllowlistMatchCount: [...counters.piiExplicitAllowlistMatches.values()].reduce((total, count) => total + count, 0),
      reservedSyntheticEmailHostnames,
      reservedSyntheticEmailSuffixes,
      explicitAllowlist: explicitPiiAllowlist.map(({ valueSha256, file, filePrefixes, ...entry }) => ({
        ...entry,
        pathScope: file ?? filePrefixes,
        matchedCount: counters.piiExplicitAllowlistMatches.get(entry.id) ?? 0,
        valueFingerprint: `sha256:${valueSha256}`,
      })),
    },
    findings,
    coverage: {
      text: "full content",
      zipAndXlsx: "entry names and inflated entry content",
      pdf: "raw bytes and FlateDecode streams",
      png: "raw bytes and textual metadata chunks",
      otherBinary: "raw ASCII and UTF-16LE strings",
      limitation: "Rasterized text in image pixels is not OCR-scanned; encrypted or unsupported archive content fails closed.",
    },
  };
}

async function discoverDeliveryRoots(workspaceRoot) {
  const roots = [];
  for (const collection of ["apps", "packages"]) {
    const collectionPath = path.join(workspaceRoot, collection);
    let entries = [];
    try {
      entries = await readdir(collectionPath, { withFileTypes: true });
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    for (const entry of entries.filter((value) => value.isDirectory()).sort((left, right) => left.name.localeCompare(right.name, "en"))) {
      const packageRelative = `${collection}/${entry.name}`;
      const packageFile = path.join(workspaceRoot, packageRelative, "package.json");
      let packageJson;
      try {
        packageJson = JSON.parse(await readFile(packageFile, "utf8"));
      } catch (error) {
        if (error?.code === "ENOENT") continue;
        throw new Error(`Cannot inspect ${packageRelative}/package.json`);
      }
      if (typeof packageJson.scripts?.build !== "string") continue;
      const relativePath = packageRelative === "apps/web"
        ? "apps/web/.next/standalone"
        : `${packageRelative}/dist`;
      roots.push({
        label: packageRelative === "apps/web" ? "web-standalone" : `${entry.name}-dist`,
        relativePath,
        absolutePath: path.join(workspaceRoot, ...relativePath.split("/")),
        required: true,
      });
    }
  }
  for (const [label, relativePath] of [["evidence", "docs/evidence"], ["verification-artifacts", "artifacts"]]) {
    roots.push({ label, relativePath, absolutePath: path.join(workspaceRoot, ...relativePath.split("/")), required: false });
  }
  return roots;
}

async function walkDirectory(directory, context) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    await walkEntry(directory, entry, context);
  }
}

async function walkEntry(directory, entry, context) {
  const filename = path.join(directory, entry.name);
  const relative = portableRelative(context.workspaceRoot, filename);
  if (entry.isSymbolicLink()) {
    if (context.scope === "delivery") context.findings.push({ file: relative, line: null, kind: "symbolic link in delivery output" });
    return;
  }
  if (entry.isDirectory()) {
    if (shouldExcludeDirectory(entry.name, relative, context.scope)) {
      context.counters.excludedDirectories += 1;
      return;
    }
    await walkDirectory(filename, context);
    return;
  }
  if (!entry.isFile()) return;
  if (shouldExcludeFile(relative, context.scope)) {
    context.counters.excludedEphemeralFiles += 1;
    return;
  }
  await inspectFile(filename, relative, context);
}

function shouldExcludeDirectory(name, relative, scope) {
  if (name === ".local" || name.startsWith(".local-")) return true;
  const excluded = scope === "source" ? sourceExcludedDirectories : deliveryExcludedDirectories;
  if (excluded.has(name)) return true;
  if (scope === "source" && sourceExcludedPrefixes.some((prefix) => relative === prefix || relative.startsWith(`${prefix}/`))) return true;
  if (scope === "delivery" && relative.includes("/.next/cache")) return true;
  if (scope === "delivery" && relative.startsWith("artifacts/.verify-local-")) return true;
  return false;
}

function shouldExcludeFile(relative, scope) {
  if (scope !== "delivery") return false;
  const basename = path.posix.basename(relative);
  return relative === reportRelativePath
    || relative === "artifacts/.verify-local.lock"
    || basename.startsWith(".verify-local-")
    || basename.endsWith(".invalidated");
}

async function inspectFile(filename, relative, context) {
  const content = await readFile(filename);
  const sha256 = createHash("sha256").update(content).digest("hex");
  context.inventory.push({ path: relative, bytes: content.length, sha256 });
  context.counters.bytes += content.length;
  if (content.length > maximumFileBytes) {
    context.findings.push({ file: relative, line: null, kind: "file exceeds fail-closed scan size limit" });
    return;
  }
  if (context.scope === "delivery") inspectDeliveryFilename(relative, context.findings);
  const extension = path.extname(relative).toLowerCase();
  const binary = binaryExtensions.has(extension) || content.includes(0);
  if (binary) {
    context.counters.binaryFiles += 1;
    inspectBinaryContent(content, relative, extension, context);
  } else {
    context.counters.textFiles += 1;
    inspectTextContentInternal(content.toString("utf8"), relative, context, true);
  }
}

function inspectDeliveryFilename(relative, findings) {
  const basename = path.posix.basename(relative).toLowerCase();
  const extension = path.posix.extname(basename);
  const forbiddenName = basename === ".env"
    || (basename.startsWith(".env.") && basename !== ".env.example")
    || ["credentials.json", "demo-access.json", "id_ed25519", "id_rsa", "platform-admin-access.json", "secrets.enc.json", "secrets.json"].includes(basename)
    || /(?:^|[-_.])(?:credential|private-key|secret-store)(?:s)?(?:[-_.]|$)/u.test(basename);
  if (forbiddenName) findings.push({ file: relative, line: null, kind: "forbidden credential or secret-store filename" });
  if (forbiddenDeliveryExtensions.has(extension)) findings.push({ file: relative, line: null, kind: `forbidden delivery extension ${extension}` });
}

function inspectBinaryContent(content, relative, extension, context) {
  inspectTextContentInternal(content.toString("latin1"), relative, context, false);
  if (content.length >= 2 && content.subarray(1, Math.min(content.length, 4096)).includes(0)) {
    inspectTextContentInternal(content.toString("utf16le"), relative, context, false);
  }
  if (extension === ".xlsx" || extension === ".zip") inspectZipContent(content, relative, extension === ".xlsx", context);
  if (extension === ".pdf") inspectPdfContent(content, relative, context);
  if (extension === ".png") inspectPngContent(content, relative, context);
}

export function inspectTextContent(content, file = "input", options = {}) {
  const findings = [];
  inspectTextContentInternal(content, file, {
    scope: options.scope ?? "delivery",
    rootLabel: options.rootLabel ?? "evidence",
    findings,
    counters: {
      piiMatchesEvaluated: 0,
      piiReservedSyntheticMatches: 0,
      piiExplicitAllowlistMatches: new Map(explicitPiiAllowlist.map(({ id }) => [id, 0])),
    },
  }, options.lineNumbers !== false);
  return findings;
}

function inspectTextContentInternal(content, file, context, lineNumbers) {
  for (const signature of signatures) {
    signature.pattern.lastIndex = 0;
    for (const match of content.matchAll(signature.pattern)) {
      if (isAllowedFixture(content, match.index, file)) continue;
      addMatchFinding(context.findings, content, file, match.index, signature.name, lineNumbers);
    }
  }
  for (const finding of credentialUrls(content, file, lineNumbers)) context.findings.push(finding);
  for (const match of content.matchAll(/(?:[A-Za-z]:\\Users\\|\/Users\/|\/home\/)[^\s<>"']+/gi)) {
    addMatchFinding(context.findings, content, file, match.index, "local user path", lineNumbers);
  }
  inspectHighConfidencePii(content, file, context, lineNumbers);
}

function inspectHighConfidencePii(content, file, context, lineNumbers) {
  for (const match of content.matchAll(/\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,63}\b/gi)) {
    context.counters.piiMatchesEvaluated += 1;
    const hostname = match[0].slice(match[0].lastIndexOf("@") + 1).toLowerCase();
    if (isReservedEmailHostname(hostname)) {
      context.counters.piiReservedSyntheticMatches += 1;
      continue;
    }
    if (isExplicitlyAllowlistedPii(file, "email", match[0], context.counters)) continue;
    addMatchFinding(context.findings, content, file, match.index, "non-reserved email address", lineNumbers);
  }
  for (const match of content.matchAll(/\b\d{3}-\d{7}-\d\b/g)) {
    context.counters.piiMatchesEvaluated += 1;
    addMatchFinding(context.findings, content, file, match.index, "national identity number pattern", lineNumbers);
  }
  for (const match of content.matchAll(/(?<![A-Za-z0-9])(?:\d[ -]?){13,19}(?![A-Za-z0-9])/g)) {
    const digits = match[0].replace(/\D/g, "");
    if (!looksLikePaymentCard(digits)) continue;
    context.counters.piiMatchesEvaluated += 1;
    addMatchFinding(context.findings, content, file, match.index, "payment card number pattern", lineNumbers);
  }
}

function isReservedEmailHostname(hostname) {
  return reservedSyntheticEmailHostnames.includes(hostname)
    || reservedSyntheticEmailSuffixes.some((suffix) => hostname.endsWith(suffix));
}

function isExplicitlyAllowlistedPii(file, kind, value, counters) {
  const portableFile = file.replaceAll("\\", "/");
  const fingerprint = createHash("sha256").update(value.toLowerCase()).digest("hex");
  const entry = explicitPiiAllowlist.find((candidate) => (candidate.file === portableFile
      || candidate.filePrefixes?.some((prefix) => portableFile.startsWith(prefix)))
    && candidate.kind === kind
    && candidate.valueSha256 === fingerprint);
  if (!entry) return false;
  counters.piiExplicitAllowlistMatches.set(entry.id, (counters.piiExplicitAllowlistMatches.get(entry.id) ?? 0) + 1);
  return true;
}

function looksLikePaymentCard(digits) {
  const recognizedIssuer = /^4\d{12}(?:\d{3})?(?:\d{3})?$/u.test(digits)
    || /^(?:5[1-5]\d{14}|2(?:2(?:2[1-9]|[3-9]\d)|[3-6]\d{2}|7(?:0\d|1\d|20))\d{12})$/u.test(digits)
    || /^3[47]\d{13}$/u.test(digits)
    || /^6(?:011|5\d{2})\d{12}$/u.test(digits);
  if (!recognizedIssuer || /^(\d)\1+$/u.test(digits)) return false;
  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = Number(digits[index]);
    if (doubleDigit) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

function inspectZipContent(content, relative, requireXlsxShape, context) {
  let entries;
  try {
    entries = extractZipEntries(content);
  } catch {
    context.findings.push({ file: relative, line: null, kind: "invalid, encrypted, oversized, or unsupported ZIP container" });
    return;
  }
  if (requireXlsxShape) {
    const names = new Set(entries.map((entry) => entry.name));
    if (!["[Content_Types].xml", "_rels/.rels", "xl/workbook.xml"].every((name) => names.has(name))) {
      context.findings.push({ file: relative, line: null, kind: "XLSX container is missing required workbook entries" });
    }
  }
  for (const entry of entries) {
    context.counters.archiveEntries += 1;
    const entryFile = `${relative}!${entry.name}`;
    const extension = path.posix.extname(entry.name).toLowerCase();
    if (forbiddenArchiveExtensions.has(extension)
      || /(?:^|\/)(?:vbaProject\.bin|activeX|embeddings)(?:\/|$)/iu.test(entry.name)) {
      context.findings.push({ file: entryFile, line: null, kind: "forbidden active or credential-bearing archive entry" });
    }
    const binary = binaryExtensions.has(extension) || entry.content.includes(0);
    if (binary) inspectBinaryContent(entry.content, entryFile, extension, context);
    else inspectTextContentInternal(entry.content.toString("utf8"), entryFile, context, true);
    if (/\.rels$/iu.test(entry.name) && /\bTargetMode\s*=\s*["']External["']/iu.test(entry.content.toString("utf8"))) {
      context.findings.push({ file: entryFile, line: null, kind: "external relationship in Office evidence" });
    }
  }
}

export function extractZipEntries(content) {
  const minimumEocdOffset = Math.max(0, content.length - 65_557);
  let eocd = -1;
  for (let offset = content.length - 22; offset >= minimumEocdOffset; offset -= 1) {
    if (content.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0) throw new Error("ZIP end record is missing");
  const disk = content.readUInt16LE(eocd + 4);
  const centralDisk = content.readUInt16LE(eocd + 6);
  const entriesOnDisk = content.readUInt16LE(eocd + 8);
  const entryCount = content.readUInt16LE(eocd + 10);
  const centralSize = content.readUInt32LE(eocd + 12);
  const centralOffset = content.readUInt32LE(eocd + 16);
  if (disk !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount || entryCount > maximumArchiveEntries
    || entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff
    || centralOffset + centralSize > eocd) throw new Error("Unsupported ZIP layout");
  const entries = [];
  let offset = centralOffset;
  let expandedBytes = 0;
  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > content.length || content.readUInt32LE(offset) !== 0x02014b50) throw new Error("Invalid central directory");
    const flags = content.readUInt16LE(offset + 8);
    const method = content.readUInt16LE(offset + 10);
    const compressedBytes = content.readUInt32LE(offset + 20);
    const expandedEntryBytes = content.readUInt32LE(offset + 24);
    const nameBytes = content.readUInt16LE(offset + 28);
    const extraBytes = content.readUInt16LE(offset + 30);
    const commentBytes = content.readUInt16LE(offset + 32);
    const localOffset = content.readUInt32LE(offset + 42);
    const nextOffset = offset + 46 + nameBytes + extraBytes + commentBytes;
    if (nextOffset > content.length || flags & 0x1 || ![0, 8].includes(method)
      || compressedBytes === 0xffffffff || expandedEntryBytes === 0xffffffff
      || expandedEntryBytes > maximumArchiveEntryBytes || expandedBytes + expandedEntryBytes > maximumArchiveExpandedBytes) {
      throw new Error("Unsafe ZIP entry");
    }
    const name = content.subarray(offset + 46, offset + 46 + nameBytes).toString(flags & 0x800 ? "utf8" : "latin1").replaceAll("\\", "/");
    if (!name || name.startsWith("/") || /^[A-Za-z]:\//u.test(name) || name.split("/").includes("..")) throw new Error("Unsafe ZIP path");
    if (localOffset + 30 > content.length || content.readUInt32LE(localOffset) !== 0x04034b50) throw new Error("Invalid local ZIP header");
    const localNameBytes = content.readUInt16LE(localOffset + 26);
    const localExtraBytes = content.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameBytes + localExtraBytes;
    if (dataOffset + compressedBytes > content.length) throw new Error("Truncated ZIP entry");
    const compressed = content.subarray(dataOffset, dataOffset + compressedBytes);
    const entryContent = method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: maximumArchiveEntryBytes });
    if (entryContent.length !== expandedEntryBytes) throw new Error("Contradictory ZIP size");
    expandedBytes += entryContent.length;
    if (!name.endsWith("/")) entries.push({ name, content: entryContent });
    offset = nextOffset;
  }
  if (offset !== centralOffset + centralSize) throw new Error("Contradictory central directory size");
  return entries;
}

function inspectPdfContent(content, relative, context) {
  if (!content.subarray(0, 8).toString("latin1").startsWith("%PDF-") || !content.subarray(Math.max(0, content.length - 1024)).includes(Buffer.from("%%EOF"))) {
    context.findings.push({ file: relative, line: null, kind: "invalid PDF container" });
    return;
  }
  const raw = content.toString("latin1");
  if (/\/(?:EmbeddedFile|JavaScript)\b|\/JS\s/u.test(raw)) {
    context.findings.push({ file: relative, line: null, kind: "active content or embedded attachment in PDF evidence" });
  }
  const streamMarker = Buffer.from("stream");
  const endMarker = Buffer.from("endstream");
  let cursor = 0;
  let streamCount = 0;
  while (streamCount < 2_000) {
    const marker = content.indexOf(streamMarker, cursor);
    if (marker < 0) break;
    const dictionary = content.subarray(Math.max(0, marker - 2048), marker).toString("latin1");
    let dataStart = marker + streamMarker.length;
    if (content[dataStart] === 13) dataStart += 1;
    if (content[dataStart] === 10) dataStart += 1;
    const end = content.indexOf(endMarker, dataStart);
    if (end < 0) break;
    if (/\/FlateDecode\b/u.test(dictionary)) {
      let compressed = content.subarray(dataStart, end);
      while (compressed.length > 0 && [10, 13, 32].includes(compressed.at(-1))) compressed = compressed.subarray(0, -1);
      try {
        const expanded = inflateSync(compressed, { maxOutputLength: maximumArchiveEntryBytes });
        inspectTextContentInternal(expanded.toString("latin1"), `${relative}!flate-stream-${streamCount + 1}`, context, false);
      } catch {
        context.findings.push({ file: relative, line: null, kind: "unreadable or oversized FlateDecode PDF stream" });
      }
    }
    cursor = end + endMarker.length;
    streamCount += 1;
  }
}

function inspectPngContent(content, relative, context) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (content.length < 20 || !content.subarray(0, 8).equals(signature)) {
    context.findings.push({ file: relative, line: null, kind: "invalid PNG container" });
    return;
  }
  let offset = 8;
  while (offset + 12 <= content.length) {
    const length = content.readUInt32BE(offset);
    const type = content.subarray(offset + 4, offset + 8).toString("ascii");
    const end = offset + 12 + length;
    if (length > maximumArchiveEntryBytes || end > content.length) {
      context.findings.push({ file: relative, line: null, kind: "invalid or oversized PNG chunk" });
      return;
    }
    const data = content.subarray(offset + 8, offset + 8 + length);
    try {
      if (type === "tEXt") inspectTextContentInternal(data.toString("latin1"), `${relative}!tEXt`, context, false);
      if (type === "zTXt") {
        const separator = data.indexOf(0);
        if (separator >= 0 && data[separator + 1] === 0) {
          inspectTextContentInternal(inflateSync(data.subarray(separator + 2), { maxOutputLength: maximumArchiveEntryBytes }).toString("utf8"), `${relative}!zTXt`, context, false);
        }
      }
      if (type === "iTXt") {
        const keywordEnd = data.indexOf(0);
        if (keywordEnd >= 0 && keywordEnd + 3 < data.length) {
          let textStart = data.indexOf(0, keywordEnd + 3);
          textStart = textStart < 0 ? -1 : data.indexOf(0, textStart + 1);
          if (textStart >= 0) {
            const text = data[keywordEnd + 1] === 1
              ? inflateSync(data.subarray(textStart + 1), { maxOutputLength: maximumArchiveEntryBytes }).toString("utf8")
              : data.subarray(textStart + 1).toString("utf8");
            inspectTextContentInternal(text, `${relative}!iTXt`, context, false);
          }
        }
      }
    } catch {
      context.findings.push({ file: relative, line: null, kind: "unreadable or oversized compressed PNG metadata" });
    }
    offset = end;
    if (type === "IEND") return;
  }
  context.findings.push({ file: relative, line: null, kind: "PNG container has no complete IEND chunk" });
}

function credentialUrls(content, file, lineNumbers) {
  const findings = [];
  const pattern = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/([^\s:/@]+):([^\s/@]+)@/gi;
  for (const match of content.matchAll(pattern)) {
    const password = match[2];
    if (!password || /^\$|^%|^\{|^<|^(?:unused|example|fixture|redacted|password|test)$/i.test(password)) continue;
    if (isAllowedFixture(content, match.index, file)) continue;
    addMatchFinding(findings, content, file, match.index, "credential embedded in service URL", lineNumbers);
  }
  return findings;
}

function isAllowedFixture(content, index, file) {
  if (!/(?:^|\/)(?:test|tests|e2e)(?:\/|$)|(?:\.test\.|\.spec\.)/iu.test(file.replaceAll("\\", "/"))) return false;
  const before = content.slice(0, index).split("\n");
  const lineEnd = content.indexOf("\n", index);
  const current = content.slice(index, lineEnd === -1 ? content.length : lineEnd);
  return `${before.at(-1) ?? ""}\n${before.at(-2) ?? ""}\n${current}`.includes("secret-scan: allow-test-fixture");
}

function addMatchFinding(findings, content, file, index, kind, lineNumbers) {
  findings.push({
    file,
    line: lineNumbers ? content.slice(0, index).split("\n").length : null,
    kind,
  });
}

function portableRelative(root, filename) {
  return path.relative(root, filename).replaceAll(path.sep, "/");
}

async function writeReport(workspaceRoot, reportPath, report) {
  const absolute = path.resolve(workspaceRoot, reportPath);
  const allowedRoot = path.join(path.resolve(workspaceRoot), "artifacts");
  if (absolute !== allowedRoot && !absolute.startsWith(`${allowedRoot}${path.sep}`)) throw new Error("Scan report must stay under artifacts/");
  await mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify({ ...report, scannedAtUtc: new Date().toISOString() }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, absolute);
}

export function runSelfTest() {
  const completePrivateKey = `-----BEGIN PRIVATE KEY-----\n${"A".repeat(96)}\n-----END PRIVATE KEY-----`;
  const unsafeUrl = "postgresql://nom_admin:" + "actual-secret-value@127.0.0.1:55432/postgres";
  const unsafeEmail = "person" + "@private-company.example.es";
  const text = `${completePrivateKey}\n${unsafeUrl}\n${unsafeEmail}\n4111 1111 1111 1111`;
  const findings = inspectTextContent(text, "docs/evidence/self-test.txt", { rootLabel: "evidence" });
  const expected = ["private key", "credential embedded in service URL", "non-reserved email address", "payment card number pattern"];
  if (!expected.every((kind) => findings.some((finding) => finding.kind === kind))) throw new Error("Secret scanner self-test missed a required signature");
  if (JSON.stringify(findings).includes("actual-secret-value") || JSON.stringify(findings).includes("4111")) {
    throw new Error("Secret scanner self-test leaked matched content in its finding shape");
  }
  if (inspectTextContent('z.string().startsWith("-----BEGIN PRIVATE KEY-----")', "validator.ts").length !== 0) {
    throw new Error("Secret scanner treated a validator prefix as a private key");
  }
  if (inspectTextContent("synthetic@example.invalid", "docs/evidence/fixture.txt", { rootLabel: "evidence" }).length !== 0) {
    throw new Error("Secret scanner rejected a reserved synthetic email domain");
  }
}

function parseArguments(argv) {
  const parsed = { scope: "source", workspaceRoot: defaultWorkspaceRoot, report: null, selfTest: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--self-test") parsed.selfTest = true;
    else if (argument === "--scope") parsed.scope = argv[++index];
    else if (argument === "--workspace") parsed.workspaceRoot = path.resolve(argv[++index]);
    else if (argument === "--report") parsed.report = argv[++index];
    else throw new Error(`Unknown argument: ${argument}`);
  }
  return parsed;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.selfTest) {
    runSelfTest();
    console.log("Secret scanner self-test passed (secrets, credential URLs and high-confidence PII detected without echoing matches).");
    if (process.argv.length === 3) return;
  }
  const report = await scanWorkspace(options.workspaceRoot, options.scope);
  if (options.report) await writeReport(options.workspaceRoot, options.report, report);
  if (report.pass) {
    console.log(`Secret/PII scan passed for ${report.scope}: ${report.fileCount} files (${report.textFileCount} text, ${report.binaryFileCount} binary), ${report.archiveEntryCount} inflated archive entries; manifest ${report.manifestSha256}.`);
    return;
  }
  console.error(`Secret/PII scan failed with ${report.findings.length} high-confidence or fail-closed finding(s):`);
  for (const finding of report.findings) console.error(`- ${finding.file}${finding.line === null ? "" : `:${finding.line}`} ${finding.kind}`);
  process.exitCode = 1;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) await main();
