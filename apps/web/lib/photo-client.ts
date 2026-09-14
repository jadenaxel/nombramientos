import type { Envelope } from "./api.ts";
import { base64UrlToBytes, bytesToBase64Url } from "./crypto-client.ts";

export const PHOTO_INPUT_MAX_BYTES = 8 * 1024 * 1024;
export const PHOTO_INPUT_MAX_EDGE = 8_192;
export const PHOTO_INPUT_MAX_PIXELS = 20_000_000;
export const PHOTO_OUTPUT_EDGE = 512;
export const PHOTO_OUTPUT_MAX_BYTES = 786_432;
export const PHOTO_OUTPUT_MEDIA_TYPE = "image/jpeg" as const;

export type PhotoInputFormat = "image/jpeg" | "image/png" | "image/webp";

export interface PhotoHeader {
  readonly mediaType: PhotoInputFormat;
  readonly width: number;
  readonly height: number;
}

export interface NormalizedPhoto {
  readonly blob: Blob;
  readonly mediaType: typeof PHOTO_OUTPUT_MEDIA_TYPE;
  readonly width: typeof PHOTO_OUTPUT_EDGE;
  readonly height: typeof PHOTO_OUTPUT_EDGE;
  readonly plaintextBytes: number;
}

export interface StoredPhotoRecord {
  readonly id: string;
  readonly memberId: string;
  readonly version: number;
  readonly mediaType: typeof PHOTO_OUTPUT_MEDIA_TYPE;
  readonly width: number;
  readonly height: number;
  readonly plaintextBytes: number;
  readonly contentHash: `sha256:${string}`;
  readonly createdAt: string;
  readonly archivedAt: string | null;
  readonly envelope: Envelope;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const acceptedMimeTypes = new Set<PhotoInputFormat>(["image/jpeg", "image/png", "image/webp"]);

export function sniffPhotoHeader(input: ArrayBuffer | Uint8Array): PhotoHeader {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (isPng(bytes)) return pngHeader(bytes);
  if (isJpeg(bytes)) return jpegHeader(bytes);
  if (isWebp(bytes)) return webpHeader(bytes);
  throw new Error("El contenido no es un JPEG, PNG o WebP reconocido.");
}

export async function inspectPhotoInput(file: File): Promise<PhotoHeader> {
  if (file.size < 32 || file.size > PHOTO_INPUT_MAX_BYTES) {
    throw new Error("La imagen debe pesar entre 32 bytes y 8 MB.");
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const header = sniffPhotoHeader(bytes);
  const declared = file.type.toLocaleLowerCase();
  if (declared && (!acceptedMimeTypes.has(declared as PhotoInputFormat) || declared !== header.mediaType)) {
    throw new Error("El tipo declarado no coincide con el contenido real de la imagen.");
  }
  assertSafeDimensions(header.width, header.height);
  return header;
}

export async function normalizePhoto(
  file: File,
  focus: { readonly x: number; readonly y: number } = { x: 0.5, y: 0.5 },
): Promise<NormalizedPhoto> {
  await inspectPhotoInput(file);
  const bitmap = await decodeBitmap(file);
  try {
    assertSafeDimensions(bitmap.width, bitmap.height);
    const canvas = document.createElement("canvas");
    canvas.width = PHOTO_OUTPUT_EDGE;
    canvas.height = PHOTO_OUTPUT_EDGE;
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) throw new Error("El navegador no pudo crear el área segura de imagen.");
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, PHOTO_OUTPUT_EDGE, PHOTO_OUTPUT_EDGE);
    const side = Math.min(bitmap.width, bitmap.height);
    const sourceX = Math.round((bitmap.width - side) * clamp01(focus.x));
    const sourceY = Math.round((bitmap.height - side) * clamp01(focus.y));
    context.drawImage(
      bitmap,
      sourceX,
      sourceY,
      side,
      side,
      0,
      0,
      PHOTO_OUTPUT_EDGE,
      PHOTO_OUTPUT_EDGE,
    );
    let blob: Blob | null = null;
    for (const quality of [0.88, 0.78, 0.68, 0.56]) {
      blob = await canvasToBlob(canvas, quality);
      if (blob.size <= PHOTO_OUTPUT_MAX_BYTES) break;
    }
    if (!blob || blob.size < 128 || blob.size > PHOTO_OUTPUT_MAX_BYTES) {
      throw new Error("La fotografía normalizada supera el límite seguro de 768 KB.");
    }
    const outputBytes = new Uint8Array(await blob.arrayBuffer());
    const verified = sniffPhotoHeader(outputBytes);
    if (
      verified.mediaType !== PHOTO_OUTPUT_MEDIA_TYPE
      || verified.width !== PHOTO_OUTPUT_EDGE
      || verified.height !== PHOTO_OUTPUT_EDGE
      || containsJpegExif(outputBytes)
    ) {
      throw new Error("El navegador no produjo una imagen normalizada sin EXIF.");
    }
    const decodedOutput = await decodeBitmap(blob);
    try {
      if (decodedOutput.width !== PHOTO_OUTPUT_EDGE || decodedOutput.height !== PHOTO_OUTPUT_EDGE) {
        throw new Error("La imagen normalizada no pudo verificarse al decodificarla.");
      }
    } finally {
      decodedOutput.close();
    }
    return {
      blob,
      mediaType: PHOTO_OUTPUT_MEDIA_TYPE,
      width: PHOTO_OUTPUT_EDGE,
      height: PHOTO_OUTPUT_EDGE,
      plaintextBytes: blob.size,
    };
  } finally {
    bitmap.close();
  }
}

export function createPhotoAad(input: {
  readonly tenantId: string;
  readonly memberId: string;
  readonly photoId: string;
  readonly version: number;
  readonly mediaType: typeof PHOTO_OUTPUT_MEDIA_TYPE;
  readonly width: number;
  readonly height: number;
  readonly plaintextBytes: number;
}) {
  return {
    tenantId: input.tenantId,
    memberId: input.memberId,
    photoId: input.photoId,
    purpose: "member-photo" as const,
    schemaVersion: 1 as const,
    version: input.version,
    mediaType: input.mediaType,
    width: input.width,
    height: input.height,
    plaintextBytes: input.plaintextBytes,
  };
}

export async function encryptPhoto(input: {
  readonly key: CryptoKey;
  readonly keyId: string;
  readonly tenantId: string;
  readonly memberId: string;
  readonly photoId: string;
  readonly version: number;
  readonly normalized: NormalizedPhoto;
}): Promise<{ readonly envelope: Envelope; readonly contentHash: `sha256:${string}` }> {
  const plain = new Uint8Array(await input.normalized.blob.arrayBuffer());
  assertNormalizedBytes(plain, input.normalized);
  const aad = createPhotoAad({
    tenantId: input.tenantId,
    memberId: input.memberId,
    photoId: input.photoId,
    version: input.version,
    mediaType: input.normalized.mediaType,
    width: input.normalized.width,
    height: input.normalized.height,
    plaintextBytes: input.normalized.plaintextBytes,
  });
  const aadBytes = encoder.encode(JSON.stringify(aad));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aadBytes },
    input.key,
    plain,
  );
  const envelope: Envelope = {
    algorithm: "AES-256-GCM",
    keyId: input.keyId,
    nonce: bytesToBase64Url(nonce),
    ciphertext: bytesToBase64Url(new Uint8Array(cipher)),
    aad: bytesToBase64Url(aadBytes),
  };
  return { envelope, contentHash: await envelopeHash(envelope) };
}

export async function decryptPhoto(input: {
  readonly key: CryptoKey;
  readonly keyId: string;
  readonly tenantId: string;
  readonly memberId: string;
  readonly photo: StoredPhotoRecord;
}): Promise<Blob> {
  if (input.photo.memberId !== input.memberId || input.photo.envelope.algorithm !== "AES-256-GCM") {
    throw new Error("La fotografía cifrada pertenece a otro contexto.");
  }
  if (input.photo.envelope.keyId !== input.keyId) throw new Error("La fotografía usa otra versión de clave.");
  if (await envelopeHash(input.photo.envelope) !== input.photo.contentHash) {
    throw new Error("La huella de la fotografía cifrada no coincide.");
  }
  const expectedAad = createPhotoAad({
    tenantId: input.tenantId,
    memberId: input.memberId,
    photoId: input.photo.id,
    version: input.photo.version,
    mediaType: input.photo.mediaType,
    width: input.photo.width,
    height: input.photo.height,
    plaintextBytes: input.photo.plaintextBytes,
  });
  assertExactObject(
    JSON.parse(decoder.decode(base64UrlToBytes(input.photo.envelope.aad))) as unknown,
    expectedAad,
  );
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64UrlToBytes(input.photo.envelope.nonce),
      additionalData: base64UrlToBytes(input.photo.envelope.aad),
    },
    input.key,
    base64UrlToBytes(input.photo.envelope.ciphertext),
  );
  const bytes = new Uint8Array(decrypted);
  if (bytes.byteLength !== input.photo.plaintextBytes) throw new Error("El tamaño autenticado de la fotografía no coincide.");
  assertNormalizedBytes(bytes, {
    mediaType: input.photo.mediaType,
    width: input.photo.width as typeof PHOTO_OUTPUT_EDGE,
    height: input.photo.height as typeof PHOTO_OUTPUT_EDGE,
    plaintextBytes: input.photo.plaintextBytes,
  });
  return new Blob([bytes], { type: PHOTO_OUTPUT_MEDIA_TYPE });
}

export function containsJpegExif(bytes: Uint8Array): boolean {
  if (!isJpeg(bytes)) return false;
  let offset = 2;
  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) return false;
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    const marker = bytes[offset];
    offset += 1;
    if (marker === undefined || marker === 0xd9 || marker === 0xda) return false;
    if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) continue;
    if (offset + 2 > bytes.length) return false;
    const length = readU16Be(bytes, offset);
    if (length < 2 || offset + length > bytes.length) return false;
    if (
      marker === 0xe1
      && length >= 8
      && String.fromCharCode(...bytes.subarray(offset + 2, offset + 8)) === "Exif\u0000\u0000"
    ) return true;
    offset += length;
  }
  return false;
}

async function envelopeHash(envelope: Envelope): Promise<`sha256:${string}`> {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
  return `sha256:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function assertNormalizedBytes(
  bytes: Uint8Array,
  metadata: Pick<NormalizedPhoto, "mediaType" | "width" | "height" | "plaintextBytes">,
): void {
  const header = sniffPhotoHeader(bytes);
  if (
    header.mediaType !== PHOTO_OUTPUT_MEDIA_TYPE
    || metadata.mediaType !== PHOTO_OUTPUT_MEDIA_TYPE
    || header.width !== metadata.width
    || header.height !== metadata.height
    || metadata.width !== metadata.height
    || metadata.width < 128
    || metadata.width > 1024
    || bytes.byteLength !== metadata.plaintextBytes
    || bytes.byteLength < 128
    || bytes.byteLength > PHOTO_OUTPUT_MAX_BYTES
    || containsJpegExif(bytes)
  ) throw new Error("La fotografía no cumple el formato normalizado y sin metadatos.");
}

function assertExactObject(actual: unknown, expected: Readonly<Record<string, unknown>>): void {
  if (!actual || typeof actual !== "object" || Array.isArray(actual)) {
    throw new Error("El contexto cifrado de la fotografía es inválido.");
  }
  const record = actual as Record<string, unknown>;
  const actualKeys = Object.keys(record).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (
    actualKeys.length !== expectedKeys.length
    || actualKeys.some((key, index) => key !== expectedKeys[index] || record[key] !== expected[key])
  ) throw new Error("La fotografía cifrada pertenece a otro contexto.");
}

async function decodeBitmap(source: Blob): Promise<ImageBitmap> {
  try {
    return await createImageBitmap(source, {
      imageOrientation: "from-image",
      premultiplyAlpha: "default",
      colorSpaceConversion: "default",
    });
  } catch {
    throw new Error("El navegador no pudo decodificar el contenido real de la imagen.");
  }
}

function canvasToBlob(canvas: HTMLCanvasElement, quality: number): Promise<Blob> {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) reject(new Error("El navegador no pudo recrear la fotografía."));
      else resolve(blob);
    }, PHOTO_OUTPUT_MEDIA_TYPE, quality);
  });
}

function assertSafeDimensions(width: number, height: number): void {
  if (
    !Number.isSafeInteger(width)
    || !Number.isSafeInteger(height)
    || width < 32
    || height < 32
    || width > PHOTO_INPUT_MAX_EDGE
    || height > PHOTO_INPUT_MAX_EDGE
    || width * height > PHOTO_INPUT_MAX_PIXELS
  ) throw new Error("Las dimensiones de la imagen no están dentro del límite seguro.");
}

function isPng(bytes: Uint8Array): boolean {
  return bytes.length >= 24
    && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
      .every((value, index) => bytes[index] === value);
}

function pngHeader(bytes: Uint8Array): PhotoHeader {
  if (
    readU32Be(bytes, 8) !== 13
    || String.fromCharCode(...bytes.subarray(12, 16)) !== "IHDR"
  ) throw new Error("La cabecera PNG no es válida.");
  return { mediaType: "image/png", width: readU32Be(bytes, 16), height: readU32Be(bytes, 20) };
}

function isJpeg(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8;
}

function jpegHeader(bytes: Uint8Array): PhotoHeader {
  let offset = 2;
  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) throw new Error("La estructura JPEG no es válida.");
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    const marker = bytes[offset];
    offset += 1;
    if (marker === undefined || marker === 0xd9 || marker === 0xda) break;
    if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) continue;
    if (offset + 2 > bytes.length) break;
    const length = readU16Be(bytes, offset);
    if (length < 2 || offset + length > bytes.length) throw new Error("La estructura JPEG está truncada.");
    if (isStartOfFrame(marker)) {
      if (length < 7) throw new Error("La cabecera de dimensiones JPEG es inválida.");
      return {
        mediaType: "image/jpeg",
        height: readU16Be(bytes, offset + 3),
        width: readU16Be(bytes, offset + 5),
      };
    }
    offset += length;
  }
  throw new Error("El JPEG no declara dimensiones decodificables.");
}

function isStartOfFrame(marker: number): boolean {
  return [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker);
}

function isWebp(bytes: Uint8Array): boolean {
  return bytes.length >= 30
    && String.fromCharCode(...bytes.subarray(0, 4)) === "RIFF"
    && String.fromCharCode(...bytes.subarray(8, 12)) === "WEBP";
}

function webpHeader(bytes: Uint8Array): PhotoHeader {
  const riffSize = readU32Le(bytes, 4) + 8;
  if (riffSize > bytes.length) throw new Error("El contenedor WebP está truncado.");
  let offset = 12;
  while (offset + 8 <= riffSize) {
    const kind = String.fromCharCode(...bytes.subarray(offset, offset + 4));
    const chunkLength = readU32Le(bytes, offset + 4);
    const data = offset + 8;
    if (data + chunkLength > riffSize) throw new Error("El contenedor WebP está truncado.");
    if (kind === "VP8X" && chunkLength >= 10) {
      return {
        mediaType: "image/webp",
        width: 1 + readU24Le(bytes, data + 4),
        height: 1 + readU24Le(bytes, data + 7),
      };
    }
    if (kind === "VP8 " && chunkLength >= 10) {
      if (bytes[data + 3] !== 0x9d || bytes[data + 4] !== 0x01 || bytes[data + 5] !== 0x2a) {
        throw new Error("La cabecera VP8 no es válida.");
      }
      return {
        mediaType: "image/webp",
        width: readU16Le(bytes, data + 6) & 0x3fff,
        height: readU16Le(bytes, data + 8) & 0x3fff,
      };
    }
    if (kind === "VP8L" && chunkLength >= 5) {
      if (bytes[data] !== 0x2f) throw new Error("La cabecera VP8L no es válida.");
      const b1 = bytes[data + 1] ?? 0;
      const b2 = bytes[data + 2] ?? 0;
      const b3 = bytes[data + 3] ?? 0;
      const b4 = bytes[data + 4] ?? 0;
      return {
        mediaType: "image/webp",
        width: 1 + b1 + ((b2 & 0x3f) << 8),
        height: 1 + ((b2 & 0xc0) >> 6) + (b3 << 2) + ((b4 & 0x0f) << 10),
      };
    }
    offset = data + chunkLength + (chunkLength % 2);
  }
  throw new Error("El WebP no declara dimensiones decodificables.");
}

function readU16Be(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
}

function readU16Le(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
}

function readU24Le(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8) | ((bytes[offset + 2] ?? 0) << 16);
}

function readU32Be(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0) * 0x1000000)
    + ((bytes[offset + 1] ?? 0) << 16)
    + ((bytes[offset + 2] ?? 0) << 8)
    + (bytes[offset + 3] ?? 0);
}

function readU32Le(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0)
    + ((bytes[offset + 1] ?? 0) << 8)
    + ((bytes[offset + 2] ?? 0) << 16)
    + ((bytes[offset + 3] ?? 0) * 0x1000000)) >>> 0;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0.5;
  return Math.min(1, Math.max(0, value));
}
