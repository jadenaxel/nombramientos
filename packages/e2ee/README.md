# `@nombramientos/e2ee`

Primitiva browser-compatible para sellar una boleta canónica por separado a dos o más
custodios. La construcción criptográfica HPKE se delega exclusivamente a
`@hpke/core@1.9.0`, sin implementación propia ni fallback:

- KEM `DHKEM(P-256, HKDF-SHA256)` (`0x0010`);
- KDF `HKDF-SHA256` (`0x0001`);
- AEAD `AES-256-GCM` (`0x0002`).

La suite corresponde a [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html). SHA-256
de Web Crypto se usa únicamente para huellas, hashes de contexto y el hash canónico del
sobre; no reemplaza ninguna operación HPKE.

## Contrato

`generateCustodianKeyPair`, `exportCustodianPublicKey`,
`exportCustodianPrivateKey`, `importCustodianPublicKey` e
`importCustodianPrivateKey` administran material P-256 por `recipientId`. La importación
recalcula la huella pública y prueba con HPKE que el par privado corresponda.

`createBallotAad` produce el AAD obligatorio y canónico con:
`tenantId`, `cycleId`, `roundId`, `purpose`, `schemaVersion`, `roundVersion`,
`candidateSetHash` y `rulesHash`. `sealBallotEnvelope` valida primero el esquema de
boleta, la lista de candidatos, cardinalidad y abstención, y luego ejecuta un sellado
HPKE nuevo para cada custodio. `openBallotEnvelope` exige el AAD esperado y las reglas
locales; nunca acepta solamente el contexto declarado dentro del sobre.

`generateCustodianSigningKeyPair` crea un par Ed25519 independiente y
`signTallyAttestation` firma el contexto canónico exacto de un manifiesto y su agregado.
Las claves privadas HPKE y Ed25519 pueden exportarse juntas únicamente mediante
`createEncryptedCustodianKeyBackup`: la copia portable queda protegida con
PBKDF2-SHA-256 (600.000 iteraciones), AES-256-GCM y AAD vinculado a tenant, dispositivo,
destinatario y fecha. `openEncryptedCustodianKeyBackup` rechaza contraseña incorrecta,
alteración o cruce de contexto antes de importar y comprobar ambos pares.

```ts
import {
  BALLOT_PURPOSE,
  BALLOT_SCHEMA_VERSION,
  createBallotAad,
  generateCustodianKeyPair,
  openBallotEnvelope,
  sealBallotEnvelope,
  toCustodianPublicKey,
} from "@nombramientos/e2ee";

const first = await generateCustodianKeyPair("custodian-1");
const second = await generateCustodianKeyPair("custodian-2");
const rules = {
  candidateIds: ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
  minSelections: 1,
  maxSelections: 1,
  allowAbstention: true,
};
const aad = await createBallotAad(
  {
    tenantId: "11111111-1111-4111-8111-111111111111",
    cycleId: "22222222-2222-4222-8222-222222222222",
    roundId: "33333333-3333-4333-8333-333333333333",
    purpose: BALLOT_PURPOSE,
    schemaVersion: BALLOT_SCHEMA_VERSION,
    roundVersion: 1,
  },
  rules,
);
const envelope = await sealBallotEnvelope({
  payload: {
    schemaVersion: BALLOT_SCHEMA_VERSION,
    selections: [rules.candidateIds[0]],
    abstain: false,
  },
  aad,
  rules,
  recipients: [toCustodianPublicKey(first), toCustodianPublicKey(second)],
});
const ballot = await openBallotEnvelope({
  envelope,
  recipient: first,
  expectedAad: aad,
  rules,
});
```

## Límites explícitos

- Es multi-destinatario, no criptografía umbral: cada custodio incluido puede abrir su
  copia completa. Quórum, separación de funciones y ceremonia de apertura quedan fuera.
- HPKE base protege confidencialidad e integridad frente al destinatario, pero no firma
  al emisor. La firma Ed25519 incluida autentica la atestación del custodio; no convierte
  la boleta en una firma del elector ni sustituye una ceremonia independiente.
- `envelopeHash` detecta corrupción y permite identificar bytes canónicos; es un digest
  público, no una firma ni prueba de autenticidad. AEAD sigue siendo la defensa ante una
  alteración cuyo hash haya sido recalculado.
- Los exports privados sin cifrar son valores transitorios para construir la copia
  cifrada y no deben persistirse. El paquete no guarda claves por sí mismo; el llamador
  debe descargar/guardar la copia cifrada, bloquear memoria y gestionar revocación.
- El sobre revela metadata de contexto, destinatarios y tamaño aproximado. Solo el payload
  de selecciones está cifrado.
- La integración de API/UI, ceremonia humana y almacenamiento local seguro se documenta
  por separado. Estas primitivas no constituyen auditoría criptográfica externa ni
  certificación de seguridad.
