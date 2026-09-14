import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import sharp from "sharp";
import { signInDemo } from "./support/demo-auth.ts";
import { localQaApiRoute } from "./support/local-api-route.ts";

type PhotoWritePayload = {
  readonly photoId: string;
  readonly expectedVersion: number;
  readonly version: number;
  readonly mediaType: "image/jpeg";
  readonly width: number;
  readonly height: number;
  readonly plaintextBytes: number;
  readonly envelope: {
    readonly algorithm: "AES-256-GCM";
    readonly keyId: string;
    readonly nonce: string;
    readonly ciphertext: string;
    readonly aad: string;
  };
  readonly contentHash: `sha256:${string}`;
};

type SyntheticPhoto = Omit<PhotoWritePayload, "expectedVersion" | "photoId"> & {
  readonly id: string;
  readonly memberId: string;
  readonly createdAt: string;
  archivedAt: string | null;
};

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;

test("authorized Chromium normalizes, encrypts, displays and archives a photo without sending original bytes", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One real Chromium execution is sufficient; photo writes are synthetic and leave Demo unchanged");
  await signInDemo(page);

  let saveWrites = 0;
  let archiveWrites = 0;
  let projectedActiveReads = 0;
  let syntheticPhoto: SyntheticPhoto | undefined;

  await page.route(localQaApiRoute(/^\/v1\/members\/[^/]+\/photo\/write-context$/u), async (route) => {
    expect(route.request().method()).toBe("GET");
    const currentVersion = syntheticPhoto?.version ?? 0;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "cache-control": "private, no-store, max-age=0", "x-request-id": "synthetic-photo-write-context" },
      body: JSON.stringify({
        data: { expectedVersion: currentVersion, nextVersion: currentVersion + 1 },
        meta: { requestId: "synthetic-photo-write-context" },
      }),
    });
  });

  await page.route(localQaApiRoute(/^\/v1\/members\/[^/]+\/photo$/u), async (route) => {
    const request = route.request();
    const memberId = decodeURIComponent(new URL(request.url()).pathname.split("/").at(-2) ?? "");
    expect(memberId).toMatch(uuidPattern);
    if (request.method() === "GET") {
      if (!syntheticPhoto || syntheticPhoto.archivedAt !== null) {
        return route.fulfill({
          status: 404,
          contentType: "application/json",
          headers: { "cache-control": "private, no-store, max-age=0", "x-request-id": "synthetic-photo-missing" },
          body: JSON.stringify({ error: { code: "PHOTO_NOT_FOUND", message: "Photograph was not found" }, meta: { requestId: "synthetic-photo-missing" } }),
        });
      }
      projectedActiveReads += 1;
      expect(syntheticPhoto.memberId).toBe(memberId);
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "cache-control": "private, no-store, max-age=0", "x-request-id": "synthetic-photo-active" },
        body: JSON.stringify({ data: syntheticPhoto, meta: { requestId: "synthetic-photo-active" } }),
      });
    }

    expect(request.method()).toBe("POST");
    saveWrites += 1;
    expect(saveWrites).toBe(1);
    expect(request.headers()["idempotency-key"]).toMatch(uuidPattern);
    expect(request.headers()["x-csrf-token"]).toBeTruthy();
    expect(request.headers()["content-type"]).toContain("application/json");
    const payload = request.postDataJSON() as PhotoWritePayload;
    expect(Object.keys(payload).sort()).toEqual([
      "contentHash", "envelope", "expectedVersion", "height", "mediaType", "photoId",
      "plaintextBytes", "version", "width",
    ]);
    expect(Object.keys(payload.envelope).sort()).toEqual(["aad", "algorithm", "ciphertext", "keyId", "nonce"]);
    expect(payload.photoId).toMatch(uuidPattern);
    expect(payload.expectedVersion).toBe(0);
    expect(payload.version).toBe(1);
    expect(payload.contentHash).toMatch(digestPattern);
    expect(payload.envelope.algorithm).toBe("AES-256-GCM");
    expect(Buffer.from(payload.envelope.nonce, "base64url")).toHaveLength(12);
    const canonicalEnvelope = JSON.stringify({
      algorithm: payload.envelope.algorithm,
      keyId: payload.envelope.keyId,
      nonce: payload.envelope.nonce,
      ciphertext: payload.envelope.ciphertext,
      aad: payload.envelope.aad,
    });
    expect(payload.contentHash).toBe(`sha256:${createHash("sha256").update(canonicalEnvelope, "utf8").digest("hex")}`);
    syntheticPhoto = {
      id: payload.photoId,
      memberId,
      version: payload.version,
      mediaType: payload.mediaType,
      width: payload.width,
      height: payload.height,
      plaintextBytes: payload.plaintextBytes,
      envelope: payload.envelope,
      contentHash: payload.contentHash,
      createdAt: "2026-09-12T12:00:00.000Z",
      archivedAt: null,
    };
    return route.fulfill({
      status: 201,
      contentType: "application/json",
      headers: { "cache-control": "private, no-store, max-age=0", "x-request-id": "synthetic-photo-save" },
      body: JSON.stringify({ data: photoMetadata(syntheticPhoto), meta: { requestId: "synthetic-photo-save" } }),
    });
  });

  await page.route(localQaApiRoute(/^\/v1\/members\/[^/]+\/photo\/archive$/u), async (route) => {
    const request = route.request();
    expect(request.method()).toBe("POST");
    archiveWrites += 1;
    expect(archiveWrites).toBe(1);
    expect(request.headers()["idempotency-key"]).toMatch(uuidPattern);
    expect(request.headers()["x-csrf-token"]).toBeTruthy();
    expect(request.headers()["content-type"]).toContain("application/json");
    expect(request.postDataJSON()).toEqual({ expectedVersion: 1 });
    if (!syntheticPhoto || syntheticPhoto.archivedAt !== null) throw new Error("The synthetic photo must be active before archival");
    syntheticPhoto.archivedAt = "2026-09-12T12:01:00.000Z";
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "cache-control": "private, no-store, max-age=0", "x-request-id": "synthetic-photo-archive" },
      body: JSON.stringify({ data: photoMetadata(syntheticPhoto), meta: { requestId: "synthetic-photo-archive" } }),
    });
  });

  await page.getByRole("link", { name: "Miembros" }).click();
  await expect(page.getByRole("heading", { name: /180 de 180 personas/ })).toBeVisible({ timeout: 30_000 });

  const sourceFilename = "private-original-name.png";
  const source = await sharp({
    create: {
      width: 640,
      height: 480,
      channels: 3,
      background: { r: 21, g: 111, b: 123 },
    },
  }).png().toBuffer();
  const sourceBase64Prefix = source.toString("base64url").slice(0, 48);
  const observedRequests: string[] = [];
  let photoGetCacheControl: string | undefined;
  page.on("request", (request) => {
    observedRequests.push(`${request.url()}\n${request.postData() ?? ""}`);
  });
  page.on("response", (response) => {
    if (response.request().method() === "GET" && response.status() === 200
      && /\/v1\/members\/[^/]+\/photo$/u.test(new URL(response.url()).pathname)) {
      photoGetCacheControl = response.headers()["cache-control"];
    }
  });

  const firstMember = page.locator("article").filter({ hasText: "M001" });
  await firstMember.getByRole("button", { name: "Foto de Miembro Demo 001" }).click();
  await expect(page.getByRole("heading", { name: "Fotografía de Miembro Demo 001" })).toBeVisible();
  await page.getByLabel("Seleccionar imagen").setInputFiles({
    name: sourceFilename,
    mimeType: "image/png",
    buffer: source,
  });
  await expect(page.getByRole("status").filter({ hasText: "Recorte seguro listo" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByAltText("Vista previa del recorte seguro")).toBeVisible();

  const save = page.getByRole("button", { name: /(?:Guardar|Reemplazar) fotografía cifrada/ });
  const [putResponse] = await Promise.all([
    page.waitForResponse((response) => response.request().method() === "POST" && /\/v1\/members\/[^/]+\/photo$/u.test(new URL(response.url()).pathname)),
    save.click(),
  ]);
  expect([200, 201]).toContain(putResponse.status());
  const requestBody = putResponse.request().postDataJSON() as {
    mediaType: string;
    version: number;
    expectedVersion: number;
    width: number;
    height: number;
    plaintextBytes: number;
    envelope: { ciphertext: string; aad: string };
  };
  expect(requestBody).toMatchObject({ mediaType: "image/jpeg", width: 512, height: 512 });
  expect(requestBody.version).toBeGreaterThan(requestBody.expectedVersion);
  expect(requestBody.plaintextBytes).toBeGreaterThan(128);
  expect(Buffer.from(requestBody.envelope.ciphertext, "base64url").byteLength).toBe(requestBody.plaintextBytes + 16);
  const aad = JSON.parse(Buffer.from(requestBody.envelope.aad, "base64url").toString("utf8")) as Record<string, unknown>;
  expect(aad).toMatchObject({ purpose: "member-photo", mediaType: "image/jpeg", width: 512, height: 512 });
  expect(Object.keys(aad).sort()).toEqual([
    "height", "mediaType", "memberId", "photoId", "plaintextBytes", "purpose",
    "schemaVersion", "tenantId", "version", "width",
  ]);
  const serializedUpload = JSON.stringify(requestBody);
  expect(serializedUpload).not.toContain(sourceFilename);
  expect(serializedUpload).not.toContain(sourceBase64Prefix);
  expect(serializedUpload).not.toContain("Exif");

  await expect(page.getByAltText(/Fotografía actual: Miembro Demo 001/)).toBeVisible({ timeout: 15_000 });
  expect(photoGetCacheControl).toContain("no-store");

  const [archiveResponse] = await Promise.all([
    page.waitForResponse((response) => response.request().method() === "POST" && /\/photo\/archive$/u.test(new URL(response.url()).pathname)),
    page.getByRole("button", { name: "Archivar fotografía" }).click(),
  ]);
  expect(archiveResponse.status()).toBe(200);
  await expect(page.getByText("Esta persona no tiene fotografía.")).toBeVisible({ timeout: 15_000 });

  expect(observedRequests.join("\n")).not.toContain(sourceFilename);
  expect(observedRequests.join("\n")).not.toContain(sourceBase64Prefix);
  expect(saveWrites).toBe(1);
  expect(archiveWrites).toBe(1);
  expect(projectedActiveReads).toBeGreaterThan(0);
  expect(syntheticPhoto?.archivedAt).toBe("2026-09-12T12:01:00.000Z");
});

function photoMetadata(photo: SyntheticPhoto) {
  return {
    id: photo.id,
    memberId: photo.memberId,
    version: photo.version,
    mediaType: photo.mediaType,
    width: photo.width,
    height: photo.height,
    plaintextBytes: photo.plaintextBytes,
    contentHash: photo.contentHash,
    createdAt: photo.createdAt,
    archivedAt: photo.archivedAt,
  };
}
