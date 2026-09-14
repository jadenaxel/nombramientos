# Arquitectura

Fecha de corte: **14 de septiembre de 2026**.

## Estado

La implementación local es un monolito modular con procesos separados para web, API y worker de aprovisionamiento. Persiste en PostgreSQL 18 aislado y dispone de herramientas locales de backup/restauración y auditoría. No es una topología de producción.

> **CIERRE DE ARQUITECTURA LOCAL ACTUAL: RECONCILIADO.** [`verify-local-final.json`](../artifacts/verify-local-final.json), ejecutado de `2026-09-14T10:56:10.4065404Z` a `11:04:21.4060919Z`, terminó `result=passed`, `overallPass=true` y `closureEligible=true`: 26 etapas —25 aprobadas y Firefox opcional aceptado—, 1.196/1.196 pruebas no-Playwright y 106 aprobadas + 54 omisiones exactas de 160 resultados Playwright, sin fallos. PostgreSQL quedó en control 26/26 hasta `026_invitation_enrollment_recovery_qualification.sql` y Demo/Ozama 38/38 hasta `036_transactional_invitation_grantor_lock.sql`, con `mismatchCount=0`, Demo 180/150 y Ozama 47 tablas/0 filas. El artefacto, de 41.090 bytes y SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6`, congela 654 archivos con huella idéntica al inicio, final y publicación: `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f`. El pase del 13-09 se conserva únicamente como [evidencia histórica content-addressed](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json). Es cierre de ingeniería local, no topología ni certificación productiva. Véanse [verification.md](verification.md) y [authentication.md](authentication.md).

> **REAL-STACK ACTUAL: APROBADO.** [`real-browser-stack-local.json`](../artifacts/real-browser-stack-local.json) registra 4/4 escenarios de `2026-09-14T10:55:31.681Z` a `10:55:43.495Z`, cleanup sin bases/roles efímeros residuales y huellas protegidas de control, Demo y Ozama sin cambios. Mide 3.953 bytes y tiene SHA-256 `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`.

## Vista general

```text
Navegador autorizado
  ├─ UI ES/EN/FR y caché remoto por tenant
  ├─ vault/índice sobre datos descifrados
  ├─ llavero tenant en memoria por `envelope.keyId`, incluida historia autorizada
  ├─ importación binaria/preview en Web Worker
  ├─ AES-GCM para contenido tenant y reportes
  ├─ HPKE de boletas por custodio + atestación Ed25519
  ├─ organigrama por ciclo y etapa sobre snapshots autorizados
  ├─ generación PDF/XLSX/CSV de 13 tipos
  └─ WebAuthn del sistema/plataforma + TOTP same-phone/QR local
             │ sesión + CSRF + idempotencia + grant step-up opaco
             ▼
API Fastify /v1
  ├─ passkey primaria, TOTP fallback y recovery_limited
  ├─ ceremonias WebAuthn y step-up de un uso ligado a operación
  ├─ política de identidad global/tenant y sesiones revocables
  ├─ autorización atómica y resolución de tenant
  ├─ workflow/transacciones/versionado y pausas de elegibilidad
  ├─ cualificaciones independientes append-only, sin efecto electoral
  ├─ organigrama separado para propuesta y elección
  ├─ report snapshots/artefactos cifrados y correcciones lineales
  ├─ analítica con contexto, denominador, versión y tiempo persistido
  └─ SSE desde outbox tenant
             │
       ┌─────┴─────────────────────────────┐
       ▼                                   ▼
Plano de control                    Base tenant por iglesia
  tenants/identidades/passkeys       miembros/catálogos/ciclos/cualificaciones
  membresías/sesiones/políticas      rondas/custodia/asignaciones
  referencias de secreto             reportes cifrados/linaje/auditoría
  provisioning jobs                  outbox
       │ credencial admin
       ▼
Worker de aprovisionamiento

Herramientas locales fuera del runtime ordinario
  ├─ backup tenant AES-GCM + restore scratch
  └─ checkpoints/anclajes Ed25519 + recibos locales
```

## Decisión estructural

Las transacciones electorales permanecen dentro de la API y una única base tenant. El worker separado procesa solo aprovisionamiento porque necesita credenciales administrativas que el proceso API ordinario no recibe.

No existe broker general, servicio de correo, almacén de objetos, KMS/HSM, SIEM o WORM productivo. Fotografías y artefactos de reporte se guardan cifrados en PostgreSQL local; cambiar a objetos modifica la frontera y exige repetir aislamiento, backup, privacidad y pentest.

## Límites de confianza

1. **Navegador:** contiene temporalmente claves tenant y plaintext autorizado. El vault conserva la generación activa y un llavero de objetos `CryptoKey` no extraíbles, indexados por `keyId`, para las generaciones históricas que el dispositivo pueda abrir. IndexedDB conserva objetos privados de dispositivo, no JWK/PKCS#8 textual; un dispositivo/JS/extensión comprometidos permanecen dentro del TCB.
2. **Web/API:** observa sesión, tenant, fase, metadatos y ciphertext. Entrega el JavaScript que realiza E2EE; por eso E2EE web no protege contra un servidor deliberadamente malicioso.
3. **Plano de control:** administra tenant, identidad mínima, membresía, sesión, referencia de secreto y trabajo de aprovisionamiento; no almacena padrón/boleta tenant.
4. **Base tenant:** una base, owner y rol runtime por iglesia; separación no depende solo de una columna `tenant_id`.
5. **Worker:** único proceso local con URL administrativa; su consulta normal se limita al plano de control y no se expone al API.
6. **Custodia:** pares HPKE/Ed25519 se generan en cliente; snapshot congela al menos dos custodios. Es multi-destinatario, no umbral.
7. **Reportes:** API proyecta por type/audience/permission; navegador genera y cifra; servidor conserva ciphertext/manifiesto y una cadena inmutable de emisiones/correcciones sin ramas.
8. **Continuidad:** backup/ledger tienen llaves separadas y ACL, pero viven en el mismo host. Producción requiere separación física/administrativa.

## Autenticación y assurance

WebAuthn usa credenciales descubribles y verificación de usuario obligatoria. Las opciones y verificaciones están ligadas a un challenge de corta vida, origen exacto, RP ID, tipo de ceremonia e identidad/sesión cuando corresponde; el servidor persiste hashes y material público, nunca una clave privada. El login primario es usernameless para no consultar la existencia de una cuenta antes de que la credencial identifique al usuario.

`device_type` y Backup Eligibility (BE) quedan fijados al alta: la base exige que `multiDevice` y BE sean equivalentes y el store rechaza cualquier cambio de ambos entre ceremonias, así como Backup State verdadero cuando BE es falso. User Verification se evalúa en cada aserción. La ceremonia de reemplazo liga la passkey elegida; conserva la anterior activa hasta verificar la nueva y ejecuta inserción/revocación en una sola transacción, por lo que un fallo o cancelación no deja a la identidad sin acceso.

Las operaciones sensibles reciben un grant opaco, breve y de un solo uso ligado a sesión, identidad, propósito y hash canónico de método/ruta/cuerpo; las rutas protegidas rechazan query strings en vez de omitirlas del vínculo. Cambiar la operación o reproducir el grant falla cerrado. `recovery_limited` no entrega permisos tenant ni llave de contenido: sólo permite restablecer autenticadores y rota/revoca sesiones al completar la recuperación.

La política global actúa como piso. `monitor` reporta metas de assurance sin bloquear la transición; `enforce` aplica AAL/passkey/postura privilegiada. Prohibiciones explícitas de método, límites de sesión, controles criptográficos y recuperación restringida permanecen activos en ambos modos. La UI actual permite a quien posee `tenant.settings.manage` editar rollout, AAL general/privilegiado, mínimos/máximo de passkeys, postura privilegiada administrable, habilitación de contraseña/TOTP/recovery codes/passkeys sincronizadas y límites de sesiones activas/inactividad/vida absoluta/TTL de step-up. Los pisos de verificación local del usuario y resistencia al phishing aparecen activados y deshabilitados para edición; la matriz efectiva de requisitos por acción se muestra en solo lectura.

Guardar una política no es un simple `UPDATE`: la misma transacción bloquea y evalúa todas las identidades activas del tenant y sus autenticadores/rutas de recuperación, rechaza atómicamente una configuración que dejaría cuentas sin ruta válida, invalida ceremonias WebAuthn y grants de step-up emitidos contra la versión anterior, y reconcilia las sesiones existentes. La reconciliación aplica el máximo por identidad, preserva preferentemente la sesión declarada como actual, acorta vida absoluta/inactividad sin extender plazos y revoca grants vinculados a sesiones expulsadas. Alta de passkeys, revocación y creación/aplicación del cupo de sesiones se serializan por identidad/transacción para cerrar carreras de primer enrolamiento, máximo de credenciales, último método de acceso y sesión excedente.

Password/TOTP, passkey y switch de tenant comparten la frontera `lock_active_authentication_context`: advisory lock de policy seguido de locks compartidos de identidad, membresía y tenant activos. Devuelve sólo un booleano desde una función `SECURITY DEFINER`, sin conceder escrituras de tabla al runtime, y ordena la emisión de sesión frente a baja/cambio de policy concurrentes.

Las migraciones control posteriores a 015 cierran el baseline global inmutable, reemplazo passkey atómico, readiness/invitación passwordless, techo de seis intentos por challenge MFA, marcador explícito `password_provisioned`, scrub fail-closed de credenciales 019-era y lock común de contexto para toda emisión de sesión. El baseline rechaza `INSERT`, `UPDATE`, `DELETE` y `TRUNCATE` runtime. Una variación futura exige una migración dedicada que transforme/revalide políticas, reconcilie sesiones e invalide WebAuthn/TOTP/grants dentro de la misma transacción. Una identidad creada sin contraseña recibe un hash Argon2id de preimagen descartada y marcador falso. La remediación histórica sólo destruye una credencial si puede reconstruir sin ambigüedad que password estaba deshabilitado al aceptarla; si no, revierte todo.

La contraseña y MFA comparten un presupuesto de fallos por identidad: al octavo fallo se abre una ventana fija de 15 minutos, incluso si los fallos MFA usan challenges nuevos, y los intentos durante el bloqueo no desplazan el vencimiento. Además, cada challenge MFA reserva como máximo seis intentos de manera atómica. Un login passkey criptográficamente válido es independiente de ese estado y lo limpia sólo al completar correctamente. Al cambiar de tenant, la API hace un preflight con la política destino antes de revocar/rotar la sesión fuente; si la assurance o el método son incompatibles, falla sin mutarla. Si es compatible, la transacción relee la política destino y limita vida absoluta, inactividad y máximo de sesiones; una evaluación posterior a la rotación cubre un endurecimiento concurrente.

Crear y aceptar una invitación es autoridad delegada, no asignación libre de roles: la función tenant ligada al contexto exige `role.manage` y una arista explícita de la matriz read-only `system_role_assignment_matrix`. La matriz separa gobierno de asignación de los permisos operativos del rol; hoy sólo `CHURCH_ADMIN` tiene aristas hacia los seis roles de sistema. La aceptación bloquea el contexto/bindings del otorgante y revalida la matriz. Desactivar identidad, membresía o tenant revoca invitaciones abiertas, y un trigger final impide activar al invitado contra un otorgante inactivo. La aceptación emite el token sólo en cookie `HttpOnly` y limita la sesión `enrollment_only`, ligada a la invitación, a diez minutos y cero permisos operativos. La UI pide contraseña de forma adaptativa sólo ante `INVITATION_PASSWORD_REQUIRED`; teléfono y PC priorizan passkey y ofrecen TOTP same-phone, QR local y clave manual como fallback. El AppShell renderiza los gates `enrollment_only`/`recovery_limited` dentro del Centro de seguridad sin entrar en un bucle de redirecciones. El detalle operativo y las dependencias de producción están en [Autenticación enterprise](authentication.md).

El navegador local usa únicamente `localhost` en los puertos web/API. Antes del UI de autenticación, las autoridades loopback-IP de puertos operativos conocidos reciben un 307 con `Location` absoluto hacia un mapa fijo `localhost`; preserva ruta/query y el navegador conserva el fragmento original. La respuesta usa `no-store`, no emite cookies y ni `Host` ni `X-Forwarded-Host` construyen el destino. `/healthz` permanece en IP con 200 y sin redirección. Los cuatro perfiles Playwright comprobaron este contrato —también con cabeceras reenviadas hostiles— y que passkey continúa disponible al llegar al origen canónico. Los endpoints que emiten cookies exigen un `Origin` canónico y el build inspecciona los chunks para impedir una API `127.0.0.1:4000` horneada. Listeners y healthchecks permanecen ligados a `127.0.0.1`.

Los forwarding headers no forman parte de la frontera confiable por defecto. Fastify usa `trustProxy=false` salvo una allowlist validada de IP/CIDR del peer inmediato; se rechaza la confianza wildcard y producción no arranca sin `API_TRUSTED_PROXY_CIDRS` explícita y no vacía. Esto protege la IP que alimenta rate limiting y señales de sesión frente a `X-Forwarded-For` arbitrario, pero la allowlist real, TLS y la topología del balanceador siguen siendo configuración/validación productivas externas.

## Paquetes

| Paquete | Responsabilidad | Estado |
|---|---|---|
| `packages/domain` | estados, permisos, elecciones, métricas y fixture | implementado; pase final 41/41 |
| `packages/e2ee` | HPKE, validación/recuento, firmas y ciclo tenant | implementado; pase final 31/31 |
| `packages/database` | 26 archivos de migración control hasta `026_invitation_enrollment_recovery_qualification.sql` y 38 tenant hasta `036_transactional_invitation_grantor_lock.sql`, credenciales/ceremonias/grants/políticas/sesiones, pools, stores, workflow, custody, worker, backup/anclajes | fuente y persistencia reconciliadas 26/26 y 38/38; cierre actual 441/441 |
| `packages/catalog` | catálogo y matriz normativa versionados | revisión canónica de contenido `2025.1.0`, 29 departamentos y 67 oficinas/cargos; paquete institucional `draft` y aprobación externa pendiente |
| `packages/i18n` | 2.404 mensajes/glosario con paridad exacta ES/EN/FR | implementado; CUA local a 320 px sin overflow y manifiestos localizados; revisión lingüística/WCAG humana externa |
| `apps/api` | Fastify, WebAuthn/passkeys, TOTP, recovery_limited, políticas/step-up, RBAC, SSE y OpenAPI 149 paths/165 operaciones/278 esquemas | implementado; cierre actual 417/417 |
| `apps/web` | UX, Centro de seguridad, passkey-first, TOTP móvil/PC, crypto cliente, importación Web Worker, analítica, fotos y reportes | implementado; cierre actual unit 227/227 y Playwright 106 aprobadas + 54 omisiones exactas/160, 0 fallos |

## Resolución de tenant

El tenant activo deriva exclusivamente de sesión y membresía vigente:

1. validar sesión, expiración/revocación y CSRF cuando aplica;
2. resolver membresía activa;
3. leer referencia/version de credencial en control;
4. obtener secreto del proveedor local autorizado;
5. crear/reusar pool por tenant+versión;
6. fijar contexto transaccional;
7. cerrar pool al rotar credencial/cambiar tenant.

IDs, query, headers, body o cookies con apariencia de tenant son datos a contrastar, no autoridad. Cambiar tenant rota sesión/CSRF, bloquea el vault, cancela consultas y elimina caché/suscripción anterior.

## Integridad y concurrencia

- Mutaciones críticas usan `Idempotency-Key` y `expectedVersion`.
- Autenticación bloquea la identidad antes de crear sesión o completar el registro, relee la política efectiva dentro de la transacción y aplica el cupo antes del commit; altas simultáneas no pueden superar el máximo ni crear dos primeras passkeys.
- Revocación bloquea la identidad, credenciales y recovery codes relevantes, reevalúa todos sus tenants y falla antes de eliminar el último camino de acceso o quebrar mínimos en `enforce`.
- Una actualización de política bloquea el conjunto tenant-wide afectado, valida readiness, invalida ceremonias WebAuthn, challenges TOTP y grants anteriores, y reconcilia cupos/deadlines de sesiones en el mismo commit; el audit registra por clase sus conteos de impacto.
- Apertura, recepción, cierre y transiciones usan locks/restricciones/transacciones.
- El recibo solo se entrega después del commit.
- Envío vs cierre y doble cierre tienen pruebas HTTP/PostgreSQL.
- El outbox se escribe en la misma transacción y SSE consulta solo eventos autorizados.
- Estados autoritativos nunca viven solo en memoria/navegador.
- Snapshots congelan electorado, reglas, lista, nombres/fotos/cargo e historia relevante.
- Cambiar elegibilidad después del freeze pausa el proceso afectado sin alterar hashes, candidaturas ni denominadores históricos.
- Resolver una pausa exige IDs/versiones esperados y evidencia cifrada. Una ronda que recibió respuestas se anula y se reemplaza; una asignación afectada solo admite salidas seguras y `CLOSE_AFTER_REPLACEMENT` exige una sustitución enlazada/auditada.
- Una `linked_designation` deriva de una asignación base del mismo ciclo, no abre ronda electoral propia y se contabiliza como función nominal (`independent=false`), no como otra carga independiente.
- Solo `church_election_after_nominating_report` y `church_election` habilitan el flujo ordinario de propuestas/papeleta. Los mecanismos de consejo/junta, junta, autoridad territorial y `ex_officio` permanecen en un procedimiento separado; el servidor devuelve `COUNCIL_BOARD_PROCEDURE_REQUIRED` en vez de inventar una vía positiva no validada.
- La aplicabilidad NM-009 se actualiza para todo el grupo histórico de procedimientos de un cargo con versiones, idempotencia, auditoría y outbox. Deshabilitarla conserva procesos, rondas, decisiones y evidencia en solo lectura, los excluye de operaciones/métricas/organigrama actuales y falla si existen rondas, decisiones, pausas, agenda o dependencias incompatibles.
- Una corrección de reporte crea una emisión nueva que supersede exactamente a la anterior; la migración tenant 029 impide mutar el linaje o crear dos sucesoras, y la operación conserva tipo, audiencia, locale, formato y alcance de filtros.
- Cada cualificación de formación, ordenación, certificación u otra condición forma un registro append-only propio. Sus revisiones tienen linaje lineal para el mismo miembro y no escriben ni infieren elegibilidad, candidatura, asignación, ronda o resultado electoral.
- Una escritura cifrada de cualificación para un tenant `real` valida y bloquea en la misma transacción la generación, el grant de la identidad y el dispositivo activos. Así, una rotación o revocación no puede intercalarse después de aceptar `envelope.keyId`; una generación `retired` sirve únicamente para historia.

SSE local no tiene garantía multiinstancia; un despliegue con broker/publicador requerirá un nuevo modelo de entrega y backpressure.

## Fuentes de verdad

| Dato | Fuente |
|---|---|
| sesión/tenant | plano de control |
| permiso | bindings versionados tenant + límite global |
| fase/cierre/recepción | transacción en base tenant |
| contenido sensible | sobre/ciphertext; plaintext solo cliente autorizado |
| boleta | sobre HPKE ligado a ronda/custodios |
| agregado publicado | manifest fijo + dos atestaciones coincidentes + estado tenant |
| métrica | datos persistidos + funciones de `packages/domain`, con período/fase/filtro/denominador/versión explícitos y `updatedAt` derivado de las mutaciones relevantes |
| catálogo/regla | versión congelada del ciclo |
| historial | snapshots/versiones inmutables por operación |
| cualificación del miembro | versiones append-only independientes; metadatos mínimos en servidor y título/emisor solo dentro de un sobre E2EE con AAD exacto; nunca fuente de elegibilidad |
| organigrama | ciclo solicitado + etapa explícita (`proposal` o `elected`) + snapshots de asignación/ciclo; nunca perfil maestro actual como sustituto histórico |
| reporte emitido | registro + manifest + ciphertext de esa emisión; `lineageRootId`, revisión y enlaces de supersesión para correcciones |
| recuperación local | manifest de backup y, para auditoría, cabeza/recibo confiable |

## Registro independiente de cualificaciones

La migración inmutable `032_member_qualification_versions.sql` crea `member_qualification_versions`; la migración incremental `033_member_qualification_envelope_shape.sql` añade el CHECK estricto del sobre sin reescribir el historial de migraciones ya aplicado. La tabla conserva formación, ordenación, certificaciones y otras condiciones documentales como una secuencia lineal e inmutable por `qualificationId`. Crear o revisar exige permiso atómico, CSRF, MFA reciente, idempotencia y control optimista de versión. El vínculo compuesto impide cambiar de miembro entre revisiones y los triggers rechazan `UPDATE`, `DELETE` y `TRUNCATE` ordinarios.

Tipo, estado explícito, fechas civiles, versión y revisor son metadatos del registro. El título y el emisor opcionales permanecen dentro de un sobre AES-256-GCM ligado mediante AAD exacto a tenant, miembro, cualificación, versión y esos metadatos. El navegador selecciona la clave por `detailsEnvelope.keyId`; no prueba la generación activa contra contenido histórico ni intenta descifrarlo con una clave distinta. Si falta la clave histórica o el plaintext autenticado no cumple el esquema cerrado, la revisión se muestra como no disponible y no se utiliza.

Los eventos de auditoría/outbox de cambio conservan solo identificadores opacos, versión y el indicador estable `eligibilityInference: false`; no duplican miembro, tipo, estado, fechas ni presencia de detalles. Esta minimización no cambia que el servidor autorizado observa los metadatos públicos del registro al atender su endpoint. En ningún caso una cualificación concede, revoca o presume elegibilidad, disponibilidad o un resultado electoral.

## Organigrama por ciclo y etapa

`GET /v1/organization` exige `organigram.read`, acepta un `cycleId` UUID opcional y una etapa cerrada `proposal | elected` (por defecto `elected`). La respuesta incluye el inventario de ciclos autorizados, el ciclo seleccionado y solo los elementos de esa etapa:

- `proposal` proyecta estados preliminares sin etiquetarlos como elección congregacional;
- `elected` sustituye cualquier plaza no elegida por una vacante sin identidad, sobre o vínculo privado;
- un ciclo histórico conserva nombres de cargo/departamento y perfiles/fotos desde snapshots congelados;
- `independent` y `linkedToId` permiten distinguir carga real de funciones nominales vinculadas;
- un `cycleId` no disponible devuelve selección vacía y no cae silenciosamente al ciclo activo.

La UI filtra por IDs estables, búsqueda sobre etiquetas ya descifradas y estado, y enlaza al centro de reportes con ciclo/departamento/etapa explícitos. Las suites focales de base, contrato y modelo cubren separación de etapas e historia; el pase Playwright global del build final quedó registrado en el cierre.

## Analítica trazable

El dashboard calcula distribución de responsabilidades por persona sobre cargas independientes (`0`, `1`, `2`, `3+`) y presenta las funciones vinculadas por separado. Los porcentajes electorales usan siempre `nonAbstainingBallots`; un denominador cero se muestra como “No aplica” en ES/EN/FR. Cada tarjeta y gráfico expone período, fase, filtros, denominador, versión de ronda activa y hora de actualización. Ese `updatedAt` proviene de la mutación persistida más reciente entre las fuentes que alimentan la vista, incluidas las recepciones, y una lectura repetida no adelanta artificialmente el reloj. Sesiones `ANULADO` quedan fuera de los agregados actuales.

## Correcciones de reportes

La migración tenant `029_report_correction_lineage.sql` añade linaje de revisiones inmutable. `POST /v1/reports/{reportId}/corrections` requiere MFA, idempotencia, versión esperada y los permisos específicos del reporte original. Solo acepta códigos de razón no sensibles y genera una emisión `pending` nueva; no modifica ni sobrescribe el artefacto anterior. Restricciones, locks y transacción garantizan una única sucesora y evitan ramas. AAD, manifiesto, auditoría y outbox incorporan el linaje; la UI identifica revisiones, explica el motivo normalizado y permite navegar entre anterior y siguiente.

## Demo y Ozama

El fixture fuente de Demo es exclusivamente sintético y define 180 miembros, 150 elegibles. El cierre actual confirmó esos mismos 180/150, control 26/26 con cabeza `026_invitation_enrollment_recovery_qualification.sql`, Demo/Ozama 38/38 y cabeza tenant `036_transactional_invitation_grantor_lock.sql`, con `pass=true`, `mismatchCount=0` y cero drift/backlog. Ozama queda `pending_activation`, no se siembra y conserva **47 tablas operativas con 0 filas**. Ambos tenants contienen la revisión canónica `2025.1.0` de 29 departamentos y 67 oficinas/cargos, pero el paquete institucional sigue `draft` a la espera de aprobación externa. Los drills históricos simétricos y el real-stack vigente preservaron exactamente las bases protegidas. No se admiten en Ozama importaciones, reportes, fixtures ni filas legacy sintéticas.

La prueba de escala crea control/tenants efímeros y los elimina por nombre exacto. No usa Demo/Ozama y verificó que la huella del control operacional no cambió.

## Continuidad

Backup local usa snapshot `REPEATABLE READ READ ONLY`, `pg_dump` 18, AES-256-GCM y restore a nombre scratch determinístico. Auditoría usa cadena SHA-256, checkpoints/anclajes Ed25519 separados y tamper drills. La verificación más reciente alcanzó 1.274 eventos, 5 anclas y secuencia 5; `verify` y las 5/5 detecciones de manipulación pasaron con cero escrituras DB. `artifacts/continuity-restart-final.json` permanece como evidencia histórica válida de 921 eventos/secuencia 2, no como fotografía de la cabeza actual.

Estas herramientas prueban el diseño local; KMS/HSM, backups fuera del host, retención, WORM y restore productivo permanecen abiertos.

## Decisiones externas

- jurisdicción, catálogo y procedimiento denominacional aplicables a Ozama;
- revisión lingüística institucional de ES/EN/FR;
- dominio RP WebAuthn definitivo, DNS/TLS/HSTS e identidad/correo productivos;
- IdP OIDC/SAML, SCIM y gobierno institucional de identidades;
- FIDO Metadata Service, allowlist AAGUID/attestation y autenticadores administrados si se exige AAL3;
- hosting, red, TLS, residencia y recuperación;
- objetos/CDN y malware scanning;
- KMS/HSM y ceremonia de llaves;
- broker/outbox multiinstancia;
- observabilidad/SIEM y WORM;
- auditoría criptográfica, pentest, accesibilidad manual con lector/teclado/dispositivos reales y revisión legal/privacidad.
