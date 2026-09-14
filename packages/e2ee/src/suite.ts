import {
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

export const HPKE_SUITE = Object.freeze({
  kem: "DHKEM(P-256, HKDF-SHA256)",
  kemId: 0x0010,
  kdf: "HKDF-SHA256",
  kdfId: 0x0001,
  aead: "AES-256-GCM",
  aeadId: 0x0002,
} as const);

export type HpkeSuiteDescriptor = typeof HPKE_SUITE;

export const hpkeSuite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

export const HPKE_INFO = new TextEncoder().encode(
  "NOMBRAMIENTOS-E2EE\u0000ballot-envelope\u0000v1",
);

