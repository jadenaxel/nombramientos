# Custodia E2EE de boletas

Esta implementación mantiene las boletas de votación opacas para API y PostgreSQL. Cada boleta se sella en el navegador, por separado, para al menos dos dispositivos custodios mediante la suite RFC 9180 exacta `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`. El servidor valida contexto, hashes y destinatarios, pero no importa claves privadas ni descifra selecciones.

## Secuencia operativa

1. Cada custodio registra la clave HPKE pública de su dispositivo y una clave pública Ed25519 SPKI. La clave privada permanece en su dispositivo.
2. Un operador con `tally.custody` congela al menos dos claves activas pertenecientes a identidades distintas para la ronda. La instantánea incluye la regla de decisión canónica de la ronda.
3. Un elector incluido en `round_elector_snapshots` consulta únicamente los recipients HPKE públicos y cifra `nombramientos.hpke-ballot-envelope` para el conjunto exacto.
4. `POST /v1/rounds/{roundId}/submissions` acepta ese sobre para rondas `vote`; las propuestas continúan usando el sobre AES del tenant. El AAD, suite, destinatarios, fingerprints, `envelopeHash` y `contentHash` deben coincidir exactamente con la ronda y custodia congeladas.
5. Después de `VOTACION_CERRADA`, un custodio fija el manifiesto. Contiene el conjunto completo y ordenado de `receiptId`, `contentHash` y `envelopeHash`, nunca identidad del elector.
6. Cada custodio congelado descarga el mismo manifiesto y descifra/valida localmente. Envía el agregado canónico completo y firma con Ed25519 el contexto canónico `tenantId / roundId / manifestId / manifestHash / aggregateHash`.
7. El servidor vuelve a validar candidatos, totales, cardinalidad, regla y decisión; calcula `aggregateHash` él mismo. Solo cuando dos identidades custodias distintas coinciden persiste `agreed_aggregate` y permite publicación.
8. La publicación cambia la ronda a `RESULTADO_INTERNO`. No equivale a elección congregacional.

Todas las mutaciones requieren sesión, CSRF e `Idempotency-Key`; las versiones esperadas aplican control optimista. Las respuestas llevan `Cache-Control: no-store`.

## Contrato HTTP implementado

| Método y ruta | Permiso | Cuerpo o resultado relevante |
| --- | --- | --- |
| `GET /v1/custody/keys` | `tally.custody` | Metadatos y material exclusivamente público de claves. |
| `POST /v1/custody/keys` | `tally.custody` | `{deviceId,recipientId,expectedVersion,suite,hpkePublicKey,hpkeFingerprint,signingAlgorithm,signingPublicKeySpki,signingFingerprint}`. |
| `POST /v1/custody/keys/{keyId}/revoke` | `tally.custody` | `{expectedVersion,reason?}`; solo la identidad propietaria puede revocar su dispositivo. |
| `GET /v1/rounds/{roundId}/custody` | `tally.custody` | Vista operativa del set congelado, incluida identidad custodia y claves públicas. |
| `POST /v1/rounds/{roundId}/custody/freeze` | `tally.custody` | `{expectedRoundVersion,keyIds}`; exige dos identidades distintas y cero boletas recibidas. |
| `GET /v1/rounds/{roundId}/custody/recipients` | `ballot.submit` | Solo para elector congelado y ronda abierta: `{roundId,roundVersion,custodyVersion,suite,recipients:[{recipientId,fingerprint,hpkePublicKey}]}`. No expone clave de firma ni identidad custodia. |
| `POST /v1/rounds/{roundId}/custody/manifest` | `tally.recount` | `{expectedRoundVersion,expectedCustodyVersion}`. |
| `GET /v1/rounds/{roundId}/custody/manifest` | `tally.recount` + custodio congelado | Manifiesto, clave pública propia congelada y sobres cifrados sin identidad electoral. |
| `POST /v1/rounds/{roundId}/custody/attestations` | `tally.recount` + custodio congelado | `{expectedManifestVersion,aggregate,signature}`. El cliente no suministra un hash autoritativo. |
| `POST /v1/rounds/{roundId}/custody/publication` | `aggregate.publish` | `{expectedRoundVersion,expectedManifestVersion}`; exige dos firmas concordantes y devuelve también el agregado acordado. |
| `GET /v1/rounds/{roundId}/custody/aggregate` | `aggregate.read` | Devuelve únicamente el agregado ya publicado, con hashes y versión. |

El agregado canónico que firma cada custodio tiene esta forma estricta:

```json
{
  "schemaVersion": 1,
  "receivedBallots": 7,
  "nonAbstainingBallots": 6,
  "abstentions": 1,
  "maxSelections": 1,
  "candidates": [
    { "candidateId": "00000000-0000-4000-8000-000000000001", "votes": 3 },
    { "candidateId": "00000000-0000-4000-8000-000000000002", "votes": 2 },
    { "candidateId": "00000000-0000-4000-8000-000000000003", "votes": 1 }
  ],
  "rule": { "kind": "PLURALITY" },
  "decision": {
    "status": "SELECTED",
    "reason": "TOP_K",
    "selectedCandidateIds": ["00000000-0000-4000-8000-000000000001"],
    "tiebreakCandidateIds": [],
    "unfilledSeats": 0
  }
}
```

`candidates` debe contener exactamente el snapshot elegible, una vez cada candidato y ordenado por `candidateId`. Para mayoría estricta, la forma canónica de regla exige todos sus campos: `{"kind":"STRICT_MAJORITY","threshold":0.5,"denominator":"NON_ABSTAINING_BALLOTS"}`. La regla debe coincidir byte-semánticamente con `rounds.decision_rule`, congelada también en la custodia y el manifiesto; el cliente no puede elegirla al escrutar.

## Límites de confianza

- HPKE multi-recipient entrega a cada custodio una copia descifrable completa; no es descifrado umbral. Dos custodios coludidos o autorizados pueden ver boletas individuales.
- La pérdida real de una clave privada no es observable por el servidor. El custodio debe revocar su clave pública; una clave congelada ausente, revocada o sustituida bloquea manifiesto, atestación y publicación en modo fail-closed.
- El agregado claro se conserva únicamente después de dos atestaciones concordantes. La discrepancia conserva hashes y firmas como evidencia y bloquea publicación.
- Las pruebas PostgreSQL usan sobres HPKE estructuralmente válidos pero con bytes opacos sintéticos porque el servidor nunca debe descifrarlos. Los roundtrips criptográficos reales y rechazos de replay/corrupción pertenecen a `packages/e2ee`.
- No hay HSM, recuperación de clave custodio, protocolo electoral verificable extremo a extremo, revisión criptográfica externa ni almacén WORM en esta capa. Esas garantías no deben inferirse de las pruebas locales.

