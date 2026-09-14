import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const workspaceRoot = path.resolve(import.meta.dirname, "..");
const outputRoot = path.resolve(workspaceRoot, process.argv[2] ?? "artifacts");
const aggregateModules = path.join(workspaceRoot, "node_modules", ".pnpm", "node_modules");

const lockBytes = await readFile(path.join(workspaceRoot, "pnpm-lock.yaml"));
const lockHash = createHash("sha256").update(lockBytes).digest("hex");
const serial = `${lockHash.slice(0, 8)}-${lockHash.slice(8, 12)}-4${lockHash.slice(13, 16)}-a${lockHash.slice(17, 20)}-${lockHash.slice(20, 32)}`;

const manifests = await readInstalledManifests();
const workspaceManifests = await readWorkspaceManifests();
for (const manifest of workspaceManifests) manifests.set(`${manifest.name}@${manifest.version}`, manifest);

const components = [...manifests.values()]
  .map(toComponent)
  .sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"], "en"));
const licenseInventory = components.map((component) => ({
  name: component.name,
  ...(component.group ? { group: component.group } : {}),
  version: component.version,
  workspace: component.properties?.some((property) => property.name === "nombramientos:workspace" && property.value === "true") ?? false,
  licenses: component.licenses?.map((choice) => choice.license.name) ?? [],
  ...(component.externalReferences ? { externalReferences: component.externalReferences } : {}),
}));
const missingLicenses = licenseInventory.filter((component) => !component.workspace && component.licenses.length === 0);

const rootManifest = JSON.parse(await readFile(path.join(workspaceRoot, "package.json"), "utf8"));
const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  serialNumber: `urn:uuid:${serial}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: {
      components: [{
        type: "application",
        name: "nombramientos-sbom-generator",
        version: "1",
      }],
    },
    component: {
      type: "application",
      name: rootManifest.name,
      version: rootManifest.version,
      "bom-ref": `pkg:npm/${encodePurlName(rootManifest.name)}@${rootManifest.version}`,
    },
    properties: [
      { name: "nombramientos:lockfile", value: "pnpm-lock.yaml" },
      { name: "nombramientos:lockfile:sha256", value: lockHash },
      { name: "nombramientos:inventory", value: "installed workspace, production and development packages" },
    ],
  },
  components,
};

await mkdir(outputRoot, { recursive: true });
await writeJson(path.join(outputRoot, "sbom.cdx.json"), bom);
await writeJson(path.join(outputRoot, "third-party-licenses.json"), {
  generatedAt: bom.metadata.timestamp,
  lockfileSha256: lockHash,
  packages: licenseInventory,
  missingLicenseMetadata: missingLicenses.map(({ name, group, version }) => ({ name, ...(group ? { group } : {}), version })),
});

console.log(`Generated CycloneDX 1.6 SBOM with ${components.length} components.`);
console.log(`License metadata missing for ${missingLicenses.length} components; review artifacts/third-party-licenses.json.`);

async function readInstalledManifests() {
  const values = new Map();
  for (const entry of await readdir(aggregateModules, { withFileTypes: true })) {
    if (entry.name === ".bin") continue;
    if (entry.name.startsWith("@")) {
      const scopeRoot = path.join(aggregateModules, entry.name);
      for (const scoped of await readdir(scopeRoot, { withFileTypes: true })) {
        await addManifest(values, path.join(scopeRoot, scoped.name, "package.json"));
      }
    } else {
      await addManifest(values, path.join(aggregateModules, entry.name, "package.json"));
    }
  }
  return values;
}

async function readWorkspaceManifests() {
  const values = [];
  for (const directory of ["apps", "packages"]) {
    const base = path.join(workspaceRoot, directory);
    for (const entry of await readdir(base, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      try {
        const manifest = JSON.parse(await readFile(path.join(base, entry.name, "package.json"), "utf8"));
        if (validManifest(manifest)) values.push({ ...manifest, nombramientosWorkspace: true });
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
  }
  return values;
}

async function addManifest(values, filename) {
  try {
    const manifest = JSON.parse(await readFile(filename, "utf8"));
    if (validManifest(manifest)) values.set(`${manifest.name}@${manifest.version}`, manifest);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function validManifest(value) {
  return value && typeof value.name === "string" && typeof value.version === "string";
}

function toComponent(manifest) {
  const scoped = /^@([^/]+)\/(.+)$/.exec(manifest.name);
  const group = scoped?.[1] ?? "";
  const name = scoped?.[2] ?? manifest.name;
  const repository = repositoryUrl(manifest.repository);
  const homepage = validHttpUrl(manifest.homepage);
  const licenses = licenseNames(manifest).map((license) => ({ license: { name: license } }));
  const externalReferences = [
    ...(repository ? [{ type: "vcs", url: repository }] : []),
    ...(homepage ? [{ type: "website", url: homepage }] : []),
  ];
  return {
    type: manifest.nombramientosWorkspace ? (manifest.name.includes("/web") || manifest.name.includes("/api") ? "application" : "library") : "library",
    ...(group ? { group } : {}),
    name,
    version: manifest.version,
    "bom-ref": `pkg:npm/${encodePurlName(manifest.name)}@${manifest.version}`,
    purl: `pkg:npm/${encodePurlName(manifest.name)}@${manifest.version}`,
    ...(manifest.nombramientosWorkspace ? { properties: [{ name: "nombramientos:workspace", value: "true" }] } : {}),
    ...(licenses.length ? { licenses } : {}),
    ...(externalReferences.length ? { externalReferences } : {}),
  };
}

function licenseNames(manifest) {
  const raw = manifest.license ?? manifest.licenses;
  const values = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  return [...new Set(values.map((value) => {
    if (typeof value === "string") return value.trim();
    if (value && typeof value.type === "string") return value.type.trim();
    return "";
  }).filter(Boolean))].sort((left, right) => left.localeCompare(right, "en"));
}

function repositoryUrl(repository) {
  const value = typeof repository === "string" ? repository : repository?.url;
  if (typeof value !== "string" || !value.trim()) return undefined;
  const normalized = value.trim()
    .replace(/^github:/, "https://github.com/")
    .replace(/^gitlab:/, "https://gitlab.com/")
    .replace(/^bitbucket:/, "https://bitbucket.org/")
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/^git@([^:]+):/, "https://$1/")
    .replace(/\.git$/, "");
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(normalized)) return `https://github.com/${normalized}`;
  return validHttpUrl(normalized);
}

function validHttpUrl(value) {
  if (typeof value !== "string" || !value.trim()) return undefined;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}

function encodePurlName(name) {
  if (!name.startsWith("@")) return encodeURIComponent(name);
  const [scope, packageName] = name.split("/");
  return `${encodeURIComponent(scope)}/${encodeURIComponent(packageName)}`;
}

async function writeJson(filename, value) {
  await writeFile(filename, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}
