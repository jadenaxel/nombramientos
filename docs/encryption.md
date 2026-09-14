# Cifrado y gestión de claves

Fecha de corte: **11 de septiembre de 2026**.

## Resumen de confianza

La implementación local tiene dos familias de claves:

1. **clave simétrica tenant por generación**, distribuida a dispositivos autorizados mediante grants HPKE, para perfiles, disponibilidad, notas, fotografías, cualificaciones, propuestas, actas y artefactos de reporte;
2. **pares de custodia por dispositivo/ronda**, HPKE para abrir boletas y Ed25519 para atestar el recuento.

El servidor conserva material público, metadatos necesarios, sobres/ciphertext y agregados autorizados. No recibe las claves privadas de dispositivos/custodios ni las selecciones de boleta en claro por el flujo implementado.

Esto no es una auditoría criptográfica independiente ni un protocolo umbral. Cada custodio incluido puede abrir su copia de cada boleta; JavaScript malicioso, dispositivo/extensión comprometidos o colusión siguen siendo riesgos.

## Clasificación

| Categoría | Tratamiento local |
|---|---|
| Identidad de cuenta, tenant, permisos y metadatos mínimos | visibles para servicios autorizados; sin E2EE |
| Identidad visible del padrón | sobre `member-display` separado bajo clave tenant; contiene sólo los campos necesarios para mostrar y buscar a la persona |
| Contacto opcional del miembro | sobre `member-contact` independiente; la API ni siquiera lo proyecta sin `member.contact.read`, y escribirlo exige `member.contact.manage` |
| Elegibilidad/disponibilidad y fotos | sobres separados bajo clave tenant; el cliente autorizado descifra |
| Cualificación | tipo/estado/fechas/versiones explícitos en el registro independiente; título y emisor opcionales en un sobre AES-256-GCM con AAD exacto y sin efecto sobre elegibilidad |
| Nota restringida | sobre separado y proyección únicamente con permiso |
| Propuesta | selección cifrada en cliente y recibo opaco después del commit |
| Boleta | HPKE independiente para cada custodio congelado |
| Manifiesto/agregado | manifiesto fijo; descifrado/recuento cliente; atestaciones Ed25519 |
| Sesiones, agenda, consentimientos y evidencia | metadatos de estado visibles; títulos y contenido sensible en sobres con AAD exacto y versión propia |
| Reporte | instantánea proyectada; archivo claro solo en navegador; ciphertext/manifiesto en servidor |
| Backup local | dump tenant cifrado con llave AES-256-GCM independiente |
| Auditoría | cadena SHA-256; checkpoint y anclaje firmados con pares Ed25519 separados |

TLS sigue siendo obligatorio en producción incluso donde existe E2EE: protege sesión, metadatos, código servido y material público.

## HPKE de boletas

`@nombramientos/e2ee` usa `@hpke/core@1.9.0` y la suite RFC 9180:

- KEM `DHKEM(P-256, HKDF-SHA256)` (`0x0010`);
- KDF `HKDF-SHA256` (`0x0001`);
- AEAD `AES-256-GCM` (`0x0002`).

Cada sobre versionado contiene destinatarios, huella SHA-256, encapsulado/ciphertext y `envelopeHash`. El contexto autenticado incluye:

```text
tenantId
cycleId
roundId
purpose
schemaVersion
roundVersion
candidateSetHash
rulesHash
```

El contexto se canonicaliza y usa como AAD. Abrir exige el AAD esperado derivado de la ronda, no el contexto declarado por el propio sobre. Se rechazan suite/versión/formato incorrectos, destinatario/huella erróneos, candidato externo, duplicado, cardinalidad, abstención mezclada, corrupción y replay contextual.

## Ceremonia y snapshot

- Cada custodio genera en navegador un par HPKE P-256 y un par Ed25519 independiente por dispositivo.
- La API almacena solo claves públicas, huellas, identidad, dispositivo, versión y estado.
- Registrar una versión nueva reemplaza la anterior; reutilizar identidad/huella de destinatario se rechaza.
- Antes del primer voto se congelan al menos dos identidades distintas. El snapshot fija llaves, huellas y versiones.
- Llave congelada ausente, reemplazada o revocada bloquea descarga, atestación o publicación.
- Cambiar RBAC no entrega retroactivamente material privado.

La comparación humana de huellas por un canal institucional independiente es obligatoria; obtener una llave desde la misma API no autentica a la persona.

## Envío y recibo

1. El cliente obtiene configuración, lista congelada y llaves públicas.
2. Valida tenant, fase, versión, candidato, cardinalidad y abstención.
3. Canonicaliza y cifra para cada destinatario con contexto nuevo.
4. Envía ciphertext con idempotencia.
5. El servidor confirma solo después del commit.
6. El recibo vincula contenido opaco, no selección.

No se reenvía automáticamente un borrador fuera de fase. Dos pestañas/reintentos y carrera contra cierre tienen pruebas HTTP/PostgreSQL específicas.

## Escrutinio

1. La ronda cerrada genera un manifiesto fijo de recibos/ciphertext.
2. Cada custodio descarga exactamente ese manifiesto y valida hash, contexto y payload.
3. El recuento se ejecuta localmente de forma determinista.
4. El custodio firma con Ed25519 `tenantId`, `roundId`, `manifestId`, `manifestHash` y `aggregateHash`.
5. Dos identidades distintas con mismo manifiesto/agregado habilitan publicación.
6. Hash distinto marca disputa; anomalía o llave ausente bloquea.
7. `aggregate.publish` publica y `aggregate.read` lee el agregado; ninguno recibe selecciones en claro.

El protocolo no oculta boletas individuales frente a un custodio. Si se exige secreto ante cada custodio o resistencia a coacción, debe adoptarse un protocolo establecido/umbral y auditarlo.

## Clave tenant y dispositivos

El [ciclo de claves](key-lifecycle.md) implementa:

- generación cliente de 32 bytes CSPRNG e ID/generación versionados;
- alta de dispositivo con llaves públicas de wrapping/recuperación;
- challenge, MFA reciente, CSRF e idempotencia;
- grants HPKE por dispositivo;
- aprobación, revocación y rotación transaccional;
- generaciones anteriores `retired` para contenido histórico;
- recuperación offline firmada;
- estado terminal de pérdida definitiva sin fabricar una llave.

El servidor no tiene escrow de la clave tenant. Perder todas las llaves y copias válidas hace irrecuperable el contenido; la UI debe declararlo y delimitar alcance.

El vault mantiene la generación activa necesaria para nuevas escrituras y un llavero en memoria por tenant y `keyId`. Después de abrir el grant activo, el cliente intenta abrir también sus grants `retired` con los dispositivos privados locales disponibles y conserva esas generaciones históricas como objetos `CryptoKey` no extraíbles. Cambiar de tenant, bloquear el vault, ocultar o abandonar la página elimina el llavero. Un grant histórico ausente, dañado o perteneciente a otro tenant no se sustituye silenciosamente por la clave actual.

Un dispositivo autorizado después de una rotación no recibe historia implícitamente. En una acción separada y con nueva confirmación de huella, el navegador abre transitoriamente cada grant histórico propio, vuelve a sellar la clave para el dispositivo destino y borra los bytes aun ante excepción. El servidor sólo registra ese grant `retired` si el destino ya tiene un grant activo de la generación actual; una generación `lost` nunca se delega. Al abrirlo, el cliente usa el modo histórico de sólo descifrado y no reemplaza la generación activa del vault. La cobertura es por generación, parcial y reanudable si el servidor limita temporalmente la ceremonia.

## Detalles E2EE de cualificaciones

El sobre de detalles de una cualificación usa AES-256-GCM y contiene únicamente `title` e `issuer` opcionales. Su AAD exacto liga `tenantId`, `memberId`, `qualificationId`, propósito, versión de esquema, versión append-only, tipo, estado y fechas civiles. El hash canónico protege el sobre completo antes de persistirlo. El CHECK de forma se agrega de manera forward-only en `033_member_qualification_envelope_shape.sql`; la migración base 032 permanece byte-for-byte inmutable.

Para una escritura nueva en un tenant `real`, el store exige dentro de la misma transacción que `envelope.keyId` corresponda a la generación activa y a un grant activo de la identidad sobre un dispositivo activo. El bloqueo de esas filas serializa la validación con rotación o revocación. Al leer historia, cada revisión selecciona la clave por su propio `envelope.keyId`; las generaciones `retired` no autorizan escrituras nuevas.

El plaintext descifrado se valida como objeto cerrado antes de presentarlo: tipos inesperados, campos adicionales, texto vacío o límites excedidos producen estado “detalles no disponibles”. No se renderiza ni se usa el valor inválido. En los eventos de cambio, metadata de audit y payload de outbox no copian título, emisor, ciphertext ni miembro/tipo/estado/fechas; conservan la referencia opaca, versión y la declaración `eligibilityInference: false` necesaria para trazabilidad mínima.

## Copias privadas

La copia de custodia o recuperación se cifra localmente con:

- PBKDF2-SHA-256, 600.000 iteraciones;
- sal aleatoria de 16 bytes;
- AES-256-GCM;
- IV aleatorio de 12 bytes;
- AAD ligado a tenant/dispositivo/destinatario/fecha;
- contraseña de 16 a 1.024 caracteres.

Contraseña incorrecta, manipulación, contexto cruzado o pares incongruentes se rechazan. La copia abierta no se envía al servidor.

## Reportes

El navegador genera bytes PDF/XLSX/CSV, calcula la huella clara, cifra mediante AES-GCM bajo la generación tenant y sube solo ciphertext/manifiesto. La AAD liga:

- tenant y report ID;
- versión de solicitud;
- tipo, audiencia, locale y formato;
- nombre/media type;
- `snapshotSha256` y `artifactSha256`.

Al recuperar, todos esos campos, hashes y tamaños se validan antes del descifrado. Una generación de clave equivocada produce un error explícito. Los bytes claros se conservan solo el tiempo necesario para descargar/imprimir y se sobreescriben en el buffer controlado, sin prometer borrado forense del navegador.

## Backup y auditoría

La llave de backup es independiente de las claves tenant y de custodia. `pg_dump` produce un archivo temporal protegido, AES-256-GCM autentica el dump contra su manifiesto y el claro se elimina en `finally`. El inventario local es exportable: producción requiere KMS/HSM y recuperación probada.

Checkpoints y anclajes usan pares Ed25519 distintos. Separación de dominio y cadenas enlazadas detectan manipulación frente a un recibo confiable. El recibo local no es WORM; debe publicarse fuera del host y dominio administrativo.

## Evidencia local

- 31/31 pruebas del paquete E2EE en el pase observado;
- pruebas live de custodia: camino coincidente, discrepancia y pérdida/revocación;
- pruebas live/unitarias/cliente/UI del ciclo tenant;
- pruebas focales puras de contrato, store, selección histórica por `keyId` y validación fail-closed de cualificaciones; `member-qualification.live.test.ts` pasó sus cuatro casos en PostgreSQL 18 de loopback el 12-09-2026, sin convertir ese resultado focal en un conteo global;
- validación de carreras de envío/cierre;
- pruebas de AAD/tamper/replay para reportes;
- pruebas de backup y anclajes;
- recorrido Playwright de ceremonia y restauración/revocación de dispositivo.

El último `pnpm verify:local` integrado debe registrarse en [verification.md](verification.md).

## Bloqueantes externos

- auditoría criptográfica independiente de suite, composición, aleatoriedad, AAD, formatos, rotación, recuperación y UX;
- ceremonia institucional supervisada de huellas/reemplazo/revocación/pérdida;
- pentest y revisión de entrega del JavaScript/CSP/cadena de build;
- KMS/HSM, llaves no exportables, separación de operadores y rotación;
- WORM/recibos fuera del host;
- análisis de metadatos, coacción y colusión;
- política de migración criptográfica y respuesta ante compromiso.
