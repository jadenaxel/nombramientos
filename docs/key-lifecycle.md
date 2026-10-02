# Ciclo de claves E2EE de tenant (AC-32)

## Garantía y límite

Para tenants `real`, la clave simétrica de contenido se genera como 32 bytes aleatorios en el cliente. Cada dispositivo genera localmente un par HPKE P-256 y conserva su clave privada; la API recibe únicamente la clave pública, su huella SHA-256 y un sobre HPKE que contiene la clave de tenant. La copia de recuperación también se crea y abre en cliente. Ningún endpoint de este módulo acepta contraseña, clave de tenant en claro, clave privada ni copia de recuperación abierta.

La autenticación local conserva sus comprobaciones de contraseña, MFA/passkey y frescura para las ceremonias. Las sesiones federadas GestionChurch delegan actualmente la autenticación al proveedor: en la fase 1 el módulo no exige un segundo factor local ni demuestra que el proveedor haya aplicado MFA. Esto no elimina los desafíos exactos, permisos, membresías ni controles de grants E2EE. La contraseña de autenticación nunca forma parte del KDF ni del sobre de la clave de tenant.

No existe escrow, clave maestra global ni endpoint de soporte que reconstruya una clave. Perder todos los grants privados y la copia offline hace que el contenido cifrado quede definitivamente irrecuperable.

## Material criptográfico

- Dispositivo: DHKEM P-256/HKDF-SHA-256, HKDF-SHA-256 y AES-256-GCM mediante HPKE.
- Clave de contenido: 32 bytes CSPRNG, identificador UUID independiente y generación monótona.
- Grant: un sobre `nombramientos.tenant-key-grant` con AAD exacto `{tenantId, tenantKeyId, generation, identityId, deviceId, deviceFingerprint}`.
- Recuperación: copia offline PBKDF2-SHA-256, 600.000 iteraciones, sal de 16 bytes, AES-256-GCM e IV de 12 bytes. Contiene la clave de tenant y una clave privada Ed25519; nunca se carga al servidor.
- Autorización de recuperación: firma Ed25519 de tenant, generación, nonce UUID de un solo uso, dispositivo/identidad destino, huella destino y hash del sobre.

Las funciones cliente viven en `packages/e2ee/src/tenant-key-lifecycle.ts`. La aplicación web conserva el par privado como objetos `CryptoKey` clonados estructuralmente en IndexedDB (`nombramientos-e2ee-devices`), nunca como JWK/PKCS#8 o texto en `localStorage`. La generación activa descifrada vive en el vault de memoria; el llavero asociado conserva como objetos `CryptoKey` no extraíbles las generaciones históricas que el dispositivo pueda abrir y las indexa por tenant y `keyId`. Bloquear, ocultar o abandonar la página, o cambiar de tenant, vacía el llavero; las copias de bytes de trabajo se sobrescriben al finalizar. La contraseña de la copia no se persiste. El alcance de protección real de IndexedDB depende de la cuenta del sistema operativo, el navegador y la integridad del JavaScript servido.

## Protocolo HTTP común

Las mutaciones del ciclo de claves requieren cookie de sesión, `X-CSRF-Token` y un `Idempotency-Key` UUID. En tenants reales, las operaciones protegidas requieren además la prueba por navegador descrita en [ADR-0008](adr/0008-device-bound-module-sessions.md); la prueba de solicitud y el desafío de la ceremonia tienen propósitos y consumos diferentes. La solicitud de la ceremonia se construye primero en cliente sin `challengeId`:

1. Enviar `POST /v1/key-lifecycle/challenges` con `{ "operation": "…", "request": <solicitud exacta> }` y una clave de idempotencia propia.
2. La API valida la política de autenticación aplicable (local o federada), permiso, membresías, estructura criptográfica y, para recuperación, la firma. Devuelve un desafío ligado a sesión, actor, operación y hash canónico exacto, con expiración de cinco minutos.
3. Enviar la mutación correspondiente con los mismos campos de `request`, sin modificación, más `challengeId`, y una segunda clave de idempotencia.

Modificar incluso un byte del sobre, destinatario, generación o razón hace fallar el consumo. Un desafío consumido, vencido o de otra sesión devuelve `KEY_LIFECYCLE_CHALLENGE_INVALID` (`428`). Repetir una mutación con la misma clave y cuerpo devuelve exactamente su resultado anterior; reutilizar la clave con otro cuerpo falla `IDEMPOTENCY_CONFLICT`.

## Endpoints e inventario OpenAPI

| Operación | Endpoint | Cuerpo `request` / respuesta principal |
|---|---|---|
| Estado | `GET /v1/key-lifecycle` | generaciones, dispositivos propios y grants propios; con `recovery.activate`, inventario administrable de dispositivos/grants para aprobar, rotar o revocar |
| Desafío | `POST /v1/key-lifecycle/challenges` | unión discriminada por `operation`; `KeyLifecycleChallenge` |
| Alta de dispositivo | `POST /v1/key-lifecycle/devices` | `deviceId`, `label`, `wrappingPublicKey`, `challengeId`; `KeyLifecycleDevice` |
| Grant inicial | `POST /v1/key-lifecycle/grants/initialize` | `deviceId`, `tenantKeyId`, `envelope`, `recoveryPublicKey`, `challengeId`; `KeyLifecycleGrant` |
| Aprobar grant | `POST /v1/key-lifecycle/grants` | identidad/dispositivo destino, key/generación, `envelope`, `challengeId`; `KeyLifecycleGrant` |
| Revocar grant | `POST /v1/key-lifecycle/grants/revoke` | `grantId`, versión, razón, confirmación de último grant, `challengeId` |
| Rotar | `POST /v1/key-lifecycle/rotations` | key/generación esperada, nueva key, nueva clave pública de recuperación, grants completos, razón y desafío |
| Recuperar | `POST /v1/key-lifecycle/recoveries` | key/destino/sobre, contexto y firma Ed25519, desafío; `KeyLifecycleGrant` |
| Declarar pérdida | `POST /v1/key-lifecycle/loss-declarations` | key, razón, literal `PERMANENTLY_LOSE_TENANT_KEY`, desafío |

El contrato actual incluye `HpkeSuite`, `WrappingPublicKey`, `RecoveryPublicKey`, `TenantKeyGrantAad`, `TenantKeyGrantEnvelope`, `TenantKeyRecoveryContext`, `TenantKeyRecoveryAuthorization`, `KeyLifecycleChallenge`, `KeyLifecycleDevice`, `KeyGenerationSummary`, `KeyLifecycleGrant`, `KeyLifecycleState` y las solicitudes mutantes correspondientes. Los validadores ejecutables están en `apps/api/src/modules/key-lifecycle-contract.ts`; las pruebas de OpenAPI exigen referencias resolubles y paridad con las rutas. `additionalProperties: false`, longitudes y enumeraciones deben permanecer alineados.

## Ceremonias operativas

La administración completa se conserva en `/{es|en|fr}/app/settings`, implementada por `apps/web/components/nombramientos/key-lifecycle-view.tsx`. El acceso integrado usa una guía inicial contextual: un navegador reconocido verifica su vínculo en segundo plano; uno nuevo prepara sus claves locales y queda pendiente de autorización explícita. La guía pendiente muestra únicamente las opciones de alta inicial, recuperación o pérdida que permitan sus roles y el estado real, no controles de administración que el servidor rechazará. No obliga a volver a Configuración para cada ingreso ni concede claves automáticamente por ser administrador.

La administración activa incluye registro y comparación de huellas, desbloqueo local, aprobación de otro dispositivo/usuario, revocación con control de versión, rotación atómica, recuperación firmada, declaración de pérdida terminal y cierre de sesiones. Para contenido protegido de tenants reales, `AppShell` usa el grant HPKE local y ya no exige el grant PBKDF2 legado de demostración. Los errores de API se traducen por código; nunca se muestra el mensaje interno del servidor. La autenticación MFA del modo independiente no se habilita en el perfil integrado GestionChurch durante esta fase.

### Primer administrador

1. Abrir el módulo desde GestionChurch con la autorización central vigente. En el modo independiente, aceptar la invitación y cumplir las comprobaciones MFA/frescura correspondientes.
2. Generar `deviceId` y par HPKE en el cliente; registrar la clave pública.
3. Generar la clave de tenant y el par Ed25519 de recuperación en el cliente.
4. Sellar un grant para el propio dispositivo y crear la copia offline cifrada.
5. Exigir que el administrador confirme que guardó y probó la copia antes de registrar el grant inicial.
6. Enviar solamente el grant HPKE y la clave pública Ed25519. Una carrera de dos inicializaciones se serializa por tenant y solo una puede ganar.

### Segundo dispositivo o usuario

1. El destinatario autenticado genera el par HPKE y registra su clave pública como `pending`; en el perfil integrado no se exige un segundo MFA local. Antes de acceder a contenido, demuestra posesión de su clave privada HPKE y enlaza su firmante independiente a la sesión.
2. Administrador y destinatario comparan la huella por un canal independiente. La respuesta de la API por sí sola no autentica la clave.
3. Un administrador que ya posee un grant activo abre localmente su grant, sella la misma clave para el dispositivo verificado y aprueba el nuevo grant con `recovery.activate`.

Asignar un rol o ser administrador global nunca crea un grant. La API comprueba por separado membresía, permiso, prueba de posesión del navegador y grant vigente del dispositivo exacto. Una sesión pendiente no puede aprobarse por disponer de otro grant de la misma identidad.

### Delegación histórica deliberada

Autorizar la generación actual y delegar historia son dos acciones distintas. Después de que el dispositivo destino está `active` y tiene un grant `active` de la generación actual, un administrador puede confirmar nuevamente su huella y completar las generaciones retiradas desde la sección de cobertura histórica. El cliente abre un grant `retired` propio con una clave privada local, vuelve a sellar esa misma clave para el dispositivo destino y pone los bytes en cero antes de enviar el sobre. Si un grant local está dañado, prueba determinísticamente otro dispositivo propio autorizado para la misma generación; la mutación HTTP se ejecuta una sola vez, únicamente después de obtener un sobre válido.

La operación reutiliza `POST /v1/key-lifecycle/grants` y su challenge exacto. Bajo el lock transaccional del ciclo, el store acepta sólo una generación `active` o `retired`, nunca `lost`. Para `retired` exige: grant retirado exacto del actor unido a dispositivo activo; dispositivo destino activo y huella coincidente; grant activo del mismo destino para la generación actual; generación y AAD exactos. El nuevo registro nace `retired` con `retired_at`; no activa dispositivos pendientes ni habilita escrituras con una clave vieja. Membresía y permiso se revalidan en la ruta antes de entrar al store.

La UI enumera cobertura por dispositivo y generación. Cada grant aceptado queda registrado de forma independiente. Un resultado parcial permanece visible y la acción de completar sigue disponible: ante un fallo transitorio o rate limit, el reintento omite las generaciones ya cubiertas. El challenge usa `preHandler`, después de autenticación y CSRF, y admite hasta 100 operaciones `grant.approve` por ventana de cinco minutos; las demás ceremonias conservan el máximo 12. Si existen más de 100 generaciones retiradas, la cobertura se reanuda deliberadamente en otra ventana. Sólo se muestra éxito global cuando todas quedaron cubiertas. Una generación sin material local válido no se sustituye por la clave actual, y una generación perdida permanece irrecuperable.

### Revocación y rotación

Revocar excluye ese grant de las operaciones de ciclo de claves, pero no puede borrar copias que un dispositivo comprometido ya extrajo. Ante compromiso se debe rotar inmediatamente. La rotación crea localmente una clave y clave de recuperación nuevas; envía un sobre independiente para cada dispositivo conservado y conmuta todo en una transacción. Los grants de la generación anterior quedan `retired`, no `revoked`, para leer contenido histórico por su `keyId` exacto; el recifrado masivo, si se autoriza, es un flujo operacional separado. Nuevas escrituras deben usar solo la generación `active`.

Desde el cambio D10 autorizado el 2 de octubre de 2026, la sesión HTTP de un tenant real está vinculada al dispositivo mediante prueba HPKE durante el alta y firmas ES256 de un uso en solicitudes protegidas. Cookie, identidad o `deviceId` declarativo no bastan. La transacción fija el vínculo de sesión y el dispositivo/grant/generación exactos; revocar un dispositivo invalida sus vínculos en esa misma base sin depender del cleanup suplementario de sesiones en control. Mantener otro dispositivo autorizado de la misma persona no reautoriza la cookie revocada. La API sigue sin validar el plaintext del ciphertext ni puede borrar claves o información extraídas previamente; rotar sigue siendo una operación separada y explícita ante compromiso.

Al desbloquear la generación activa, la UI intenta abrir además cada grant propio `retired` cuyo dispositivo privado todavía exista localmente. Cada clave histórica se incorpora al llavero bajo el `tenantKeyId` exacto y los consumidores eligen mediante `envelope.keyId`; nunca se prueba el contenido antiguo con la generación actual. Que un grant histórico no esté disponible o no autentique no bloquea la generación activa: esa revisión se degrada de forma cerrada a “detalles no disponibles”. Esto preserva historia autorizada, no equivale a recifrado ni recupera una clave perdida.

### Recuperación y pérdida

Para recuperar, se abre la copia offline localmente, se registra un dispositivo nuevo, se sella la clave recuperada para él y se firma el contexto exacto. La API verifica la clave pública registrada y consume el nonce una sola vez. Recuperar la cuenta o usar códigos TOTP no entrega material E2EE.

El último grant online puede revocarse únicamente con `confirmLastActiveGrant: true`. Mientras exista la copia offline, aún se puede recuperar. Si se perdió o destruyó, el administrador puede declarar la key perdida solo cuando no quedan grants activos y escribiendo el literal de confirmación. El estado `lost` rechaza toda recuperación con `TENANT_KEY_PERMANENTLY_LOST` (`410`); la base conserva únicamente evidencia pública/auditable.

## Concurrencia, auditoría y metadatos

Las transacciones toman un advisory lock exclusivo por base de tenant, además de restricciones únicas sobre generación activa, dispositivo/generación y nonce de recuperación. Esto hace atómicas inicialización, aprobación, revocación, rotación y pérdida. No se permiten `DELETE` ni `TRUNCATE` al runtime.

Los stores que escriben contenido protegido deben validar todos los `envelope.keyId` dentro de su propia transacción. El guard común separa Demo (`device_key_grants`) de tenants reales (`e2ee_key_generations` + `e2ee_key_grants` + `e2ee_key_devices`), exige estado activo y toma `FOR SHARE` sobre tenant, generación, grant y dispositivo antes de insertar. En el perfil real fija además `sessionId` y `provenDeviceId` del vínculo HTTP; no selecciona otro grant de la identidad como sustituto. El orden de locks compartidos/exclusivos serializa las operaciones frente a revocación y rotación; una generación que ya quedó `retired` no puede autorizar otra versión nueva.

La migración aditiva039 añade tres tablas de metadatos HTTP, índices y dos triggers. Los nonces caducados se limpian en lotes máximos de500 mediante un trigger de sentencia propiedad del rol NOLOGIN del tenant, `SECURITY DEFINER` con `search_path=pg_catalog`, sin `DELETE` ni `EXECUTE` directo para runtime/PUBLIC. No elimina auditoría, grants, claves, sesiones ni negocio. El servidor determina expiración e `issuedAt`: el reloj del celular no se usa como autoridad para emitir firmas. Una conexión SSE presenta una prueba al abrir y revalida la sesión de origen exacta, dispositivo y grant vigente; la prueba inicial no se reutiliza como autorización ilimitada.

La lectura autenticada de sesión devuelve su identificador exacto y la hora del servidor, sin extender la expiración absoluta; conserva la renovación de inactividad ya existente. La preparación del navegador usa ese identificador junto con identidad, tenant, fuente y firmante local antes de habilitar consultas protegidas. La navegación normal conserva el contexto de esa misma sesión; cierre, expiración, revocación y cambio de iglesia/identidad mantienen sus limpiezas explícitas. Un reloj local desajustado no sustituye la validación del servidor.

Perder la clave de firma no permite sobrescribir una asociación inmutable. El reemplazo requiere otro navegador o un perfil nuevo y un alta/aprobación o recuperación explícita, sin borrar las claves antiguas; la guía no reemplaza el dispositivo dentro del perfil que conserva los registros anteriores.

La auditoría guarda ids opacos, operación, hashes de solicitud/sobre, huellas públicas, versiones, conteos y resultado. No guarda ciphertext completo, claves, contraseñas, firmas ni material privado. El servidor sigue observando quién registra o autoriza un dispositivo, cuándo, para qué tenant, tamaños de peticiones, huellas y cantidad de destinatarios.

## Verificación local

El corte D10 del 2 de octubre de 2026 se documenta separadamente en [GestionChurch](X:/CODE/GestionChurch/docs/premium-device-sessions-2026-10-02.md), con resultados API/DB/criptografía y navegador identificados por build. El navegador integrado del build `lBS4__cY65O1NCqX7bET8` aprobó4/4 casos, incluidas ambas reentradas después de cerrar sesiones, aprobación explícita y revocación de B conservando A. Se verificaron geometría/foco ES/EN/FR en anchos seleccionados y reloj cliente adelantado24 horas; no equivalen a pruebas físicas, revisión humana ni pentest independiente. El diagnóstico real de429 del conector se resolvió con presupuestos internos acotados, sin cachear autoridad ni relajar revocación. Los resultados históricos siguientes no acreditan automáticamente el protocolo nuevo ni sus recorridos actuales.

```powershell
pnpm --filter @nombramientos/e2ee typecheck
node packages/e2ee/node_modules/vitest/vitest.mjs run packages/e2ee/test/tenant-key-lifecycle.test.ts
pnpm --filter @nombramientos/database typecheck
pnpm --filter @nombramientos/database test test/key-lifecycle-historical-grant.test.ts
$env:NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION='true'; node packages/database/node_modules/vitest/vitest.mjs run packages/database/test/key-lifecycle.live.test.ts
$env:NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION='true'; node packages/database/node_modules/vitest/vitest.mjs run packages/database/test/member-qualification.live.test.ts
pnpm --filter @nombramientos/api typecheck
pnpm --filter @nombramientos/api test test/key-lifecycle-contract.test.ts test/key-lifecycle-routes.test.ts
pnpm --filter @nombramientos/web typecheck
pnpm --filter @nombramientos/web exec node --test lib/historical-key-delegation.test.ts lib/key-lifecycle-client.test.ts
node node_modules/@playwright/test/cli.js test e2e/key-lifecycle.spec.ts --project=desktop-chromium-es # desde apps/web
```

La prueba live solo usa PostgreSQL 18 de loopback en el puerto `55432`, crea dos bases con nombres aleatorios validados, demuestra aislamiento y elimina exactamente ambas al terminar. Con `NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true` falla en vez de omitir si el clúster no está disponible.

La prueba focal de cualificaciones crea y elimina únicamente una base efímera con nombre validado. El 12-09-2026 pasó 4/4 casos: append-only/idempotencia y minimización, bloqueo concurrente frente a rotación, rechazo de una generación retirada para nuevas escrituras y CHECK estricto/rollback. El CHECK vive en la migración incremental 033 para conservar intacto el checksum ya aplicado de 032. Ese resultado no sustituye el marcador de cierre global.

La fuente focal separa onboarding y backfill, cubre locks/autoridades de generaciones retiradas, replay exacto, rechazo `lost`, membresía/AAD/huella, zeroization, fallback entre dispositivos locales y apertura del mismo contenido histórico desde un dispositivo incorporado después de rotar. El pase PostgreSQL/live y el `pnpm verify:local` actual quedaron verdes dentro del cierre integral de 14-09-2026: 25 etapas aprobadas, una sonda Firefox `accepted-optional`, 1.196/1.196 pruebas no Playwright y Playwright con 106 aprobadas, 54 exclusiones exactas permitidas y 0 fallos. La huella de 654 archivos fuente permaneció idéntica al inicio, final y publicación. Son totales agregados del producto, no una auditoría criptográfica independiente; véase [verification.md](verification.md).

## Pendientes que no deben ocultarse

- Falta una revisión criptográfica independiente de composición, UX de autenticación de huellas, almacenamiento local y respuesta ante compromiso.
- La rotación conserva acceso histórico mediante grants `retired`; el recifrado masivo y su evidencia operacional son un flujo separado.
- Un servidor que distribuya JavaScript malicioso o un dispositivo comprometido puede capturar claves en uso; esta limitación inherente de E2EE web permanece.
