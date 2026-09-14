import assert from "node:assert/strict";
import test from "node:test";
import {
  PHOTO_OUTPUT_EDGE,
  PHOTO_OUTPUT_MEDIA_TYPE,
  containsJpegExif,
  createPhotoAad,
  decryptPhoto,
  encryptPhoto,
  sniffPhotoHeader,
} from "./photo-client.ts";

const tenantId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const photoId = "33333333-3333-4333-8333-333333333333";

test("sniffs real PNG/JPEG/WebP signatures and dimensions instead of trusting names", () => {
  assert.deepEqual(sniffPhotoHeader(png(640, 480)), { mediaType: "image/png", width: 640, height: 480 });
  assert.deepEqual(sniffPhotoHeader(jpeg(512, 512)), { mediaType: "image/jpeg", width: 512, height: 512 });
  assert.deepEqual(sniffPhotoHeader(webpExtended(320, 240)), { mediaType: "image/webp", width: 320, height: 240 });
  assert.throws(() => sniffPhotoHeader(new TextEncoder().encode("person.jpg is not an image")), /contenido/u);
});

test("detects JPEG EXIF segments that a normalized canvas export may not retain", () => {
  assert.equal(containsJpegExif(jpeg(512, 512, true)), true);
  assert.equal(containsJpegExif(jpeg(512, 512)), false);
});

test("encrypts only normalized bytes and rejects tenant/object replay before display", async () => {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const bytes = jpeg(PHOTO_OUTPUT_EDGE, PHOTO_OUTPUT_EDGE);
    const normalized = {
      blob: new Blob([new Uint8Array(bytes).buffer], { type: PHOTO_OUTPUT_MEDIA_TYPE }),
      mediaType: PHOTO_OUTPUT_MEDIA_TYPE,
      width: PHOTO_OUTPUT_EDGE,
      height: PHOTO_OUTPUT_EDGE,
      plaintextBytes: bytes.byteLength,
    } as const;
    const sealed = await encryptPhoto({
      key,
      keyId: "tenant-key-v1",
      tenantId,
      memberId,
      photoId,
      version: 1,
      normalized,
    });
    assert.equal(sealed.envelope.ciphertext.includes("Exif"), false);
    const stored = {
      id: photoId,
      memberId,
      version: 1,
      mediaType: PHOTO_OUTPUT_MEDIA_TYPE,
      width: PHOTO_OUTPUT_EDGE,
      height: PHOTO_OUTPUT_EDGE,
      plaintextBytes: bytes.byteLength,
      contentHash: sealed.contentHash,
      createdAt: new Date(0).toISOString(),
      archivedAt: null,
      envelope: sealed.envelope,
    } as const;
    const opened = await decryptPhoto({ key, keyId: "tenant-key-v1", tenantId, memberId, photo: stored });
    assert.deepEqual(new Uint8Array(await opened.arrayBuffer()), bytes);
    await assert.rejects(decryptPhoto({
      key,
      keyId: "tenant-key-v1",
      tenantId: "11111111-1111-4111-8111-111111111112",
      memberId,
      photo: stored,
    }), /otro contexto/u);
});

test("builds the same exact, metadata-minimal AAD used by the API", () => {
    assert.deepEqual(createPhotoAad({
      tenantId,
      memberId,
      photoId,
      version: 2,
      mediaType: PHOTO_OUTPUT_MEDIA_TYPE,
      width: 512,
      height: 512,
      plaintextBytes: 4_096,
    }), {
      tenantId,
      memberId,
      photoId,
      purpose: "member-photo",
      schemaVersion: 1,
      version: 2,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: 4_096,
    });
});

function jpeg(width: number, height: number, withExif = false): Uint8Array {
  const exif = withExif
    ? [0xff, 0xe1, 0x00, 0x0a, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x00, 0x00]
    : [];
  const core = [
    0xff, 0xd8,
    ...exif,
    0xff, 0xc0, 0x00, 0x11, 0x08,
    (height >> 8) & 0xff, height & 0xff,
    (width >> 8) & 0xff, width & 0xff,
    0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
    0xff, 0xd9,
  ];
  return Uint8Array.from([...core, ...new Array(Math.max(0, 160 - core.length)).fill(0)]);
}

function png(width: number, height: number): Uint8Array {
  const value = new Uint8Array(32);
  value.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  new DataView(value.buffer).setUint32(8, 13, false);
  value.set([0x49, 0x48, 0x44, 0x52], 12);
  new DataView(value.buffer).setUint32(16, width, false);
  new DataView(value.buffer).setUint32(20, height, false);
  return value;
}

function webpExtended(width: number, height: number): Uint8Array {
  const value = new Uint8Array(30);
  value.set(new TextEncoder().encode("RIFF"), 0);
  new DataView(value.buffer).setUint32(4, 22, true);
  value.set(new TextEncoder().encode("WEBPVP8X"), 8);
  new DataView(value.buffer).setUint32(16, 10, true);
  writeU24Le(value, 24, width - 1);
  writeU24Le(value, 27, height - 1);
  return value;
}

function writeU24Le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >> 8) & 0xff;
  bytes[offset + 2] = (value >> 16) & 0xff;
}
