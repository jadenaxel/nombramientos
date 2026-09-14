# Verificación local

Fecha de corte: **14 de septiembre de 2026**.

Este registro describe evidencia ejecutada en un único equipo Windows con datos sintéticos. “Aprobado” significa aprobado dentro de ese laboratorio y alcance; no significa certificación institucional, legal, WCAG, ASVS, criptográfica ni autorización de producción.

## Estado del cierre

> **VERIFY INTEGRAL VIGENTE: APROBADO EN LABORATORIO LOCAL.** El pase publicado entre `2026-09-14T10:56:10.4065404Z` y `2026-09-14T11:04:21.4060919Z` registró `result: "passed"`, `overallPass: true`, `closureEligible: true`: 26 etapas, de las cuales 25 quedaron `passed`, el probe Firefox opcional quedó `accepted-optional` y ninguna falló.

El artefacto sanitizado vigente [`artifacts/verify-local-final.json`](../artifacts/verify-local-final.json) mide 41.090 bytes y tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6`. Su huella fuente fue idéntica al inicio, final y publicación: `sha256:e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f` sobre 654 archivos. El fingerprint excluye de forma explícita `next-env.d.ts`, que Next.js genera y alterna entre referencias de desarrollo y producción; una prueba contractual comprueba esa exclusión sin dejar de detectar cambios de fuente reales. El pase verde del 13-09 se conserva únicamente como evidencia histórica en [`verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json`](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json), nunca bajo el alias canónico actual.

### Autenticación enterprise incluida en el cierre vigente

La ampliación inicial implementó passkeys/WebAuthn como método primario, TOTP como fallback configurable, recuperación `recovery_limited`, inventario/revocación de credenciales y sesiones, step-up de un solo uso ligado a la operación y política global/tenant. Su diseño y límites están en [Autenticación enterprise](authentication.md).

El pase integral vigente incorporó toda la ampliación y su endurecimiento: typecheck, lint y build aprobaron; web unit aprobó 227/227 y la matriz Playwright obligatoria completó 106 aprobadas, 54 skips intencionales allowlisted exactos y 0 fallos de 160 resultados. Incluye recorridos de escritorio, móvil 412 px, móvil 320 px y WebKit móvil, además del redirect canónico desde loopback-IP en los cuatro perfiles; axe automatizado, foco y ausencia de overflow aportan evidencia local, pero no sustituyen una evaluación WCAG humana.

### Endurecimiento cubierto por el marcador integral

El Centro de seguridad edita los cuatro toggles de método —contraseña, TOTP, recovery codes y passkeys sincronizadas— y los cuatro límites de sesión —máximo activo, inactividad, vida absoluta y TTL de step-up—, además de rollout/AAL/cantidades/postura. Verificación de usuario y resistencia al phishing permanecen como pisos visibles e inmutables; la matriz de requisitos por acción es de solo lectura.

La fuente de persistencia y sus casos focales incorporan readiness tenant-wide dentro del commit de política, serialización de registros/revocaciones/cupo de sesiones, reconciliación de sesiones existentes e invalidación de ceremonias WebAuthn, challenges TOTP y grants creados contra la política anterior. [`enterprise-auth-invariants.live.test.ts`](../packages/database/test/enterprise-auth-invariants.live.test.ts) define carreras de primeras passkeys y máximo, revocaciones concurrentes, rollback de una policy no preparada, invalidación posterior y reconciliación de conteos/deadlines. [`control-store.ts`](../packages/database/src/control-store.ts) aplica un presupuesto de fallos identidad-wide compartido por contraseña y MFA, con bloqueo fijo al octavo fallo durante 15 minutos, además del clamping transaccional de creación/rotación de sesión; [`platform-control.live.test.ts`](../packages/database/test/platform-control.live.test.ts) define los casos live del baseline, lock fijo, acumulación entre challenges MFA y cupo concurrente. Cada challenge MFA queda limitado además a seis reservas atómicas de intento mediante [`020_mfa_challenge_attempt_ceiling.sql`](../packages/database/migrations/control/020_mfa_challenge_attempt_ceiling.sql). [`auth-policy.test.ts`](../apps/api/test/auth-policy.test.ts) define el preflight de policy destino y el rechazo antes de mutar la sesión fuente.

Las migraciones control [`016`](../packages/database/migrations/control/016_immutable_identity_policy_baseline.sql)–[`021`](../packages/database/migrations/control/021_explicit_password_provisioning.sql) cierran baseline, reemplazo passkey, readiness/invitación passwordless, techo MFA y marcador de contraseña. [`022_legacy_invitation_password_scrub.sql`](../packages/database/migrations/control/022_legacy_invitation_password_scrub.sql) destruye únicamente una credencial 019-era cuya policy passwordless puede probarse, revoca sus sesiones/challenges/grants derivados y aborta todo si la historia es ambigua. [`023_atomic_authentication_context_lock.sql`](../packages/database/migrations/control/023_atomic_authentication_context_lock.sql) ordena policy y estado activo identidad/membresía/tenant para toda emisión de sesión. [`024_invitation_grantor_revocation_boundary.sql`](../packages/database/migrations/control/024_invitation_grantor_revocation_boundary.sql) revoca invitaciones abiertas cuando se pierde autoridad y añade el guard final de activación. [`025_initial_admin_onboarding_recovery.sql`](../packages/database/migrations/control/025_initial_admin_onboarding_recovery.sql) agrega recuperación controlada del onboarding inicial y [`026_invitation_enrollment_recovery_qualification.sql`](../packages/database/migrations/control/026_invitation_enrollment_recovery_qualification.sql) califica de forma explícita la recuperación durante enrolamiento por invitación.

En tenant, [`035_system_role_assignment_matrix.sql`](../packages/database/migrations/tenant/035_system_role_assignment_matrix.sql) separa gobierno de roles de sus permisos operativos mediante una matriz DB read-only —actualmente sólo `CHURCH_ADMIN` puede asignar los seis roles de sistema—; [`036_transactional_invitation_grantor_lock.sql`](../packages/database/migrations/tenant/036_transactional_invitation_grantor_lock.sql) bloquea bindings activos antes de evaluar invitación y mutaciones locales de acceso. Para un upgrade legacy, [`legacy-invitation-reconciliation.ts`](../packages/database/src/legacy-invitation-reconciliation.ts) construye evidencia uno-a-uno desde procedencia tenant y aceptación control, la liga al approval v2, instala únicamente un manifiesto `pg_temp` parametrizado y exige backfill/fence exactos dentro del commit 036. Ambigüedad revierte toda la migración; una caída entre el commit tenant y el control converge en el siguiente apply mediante marcador initial-admin y auditoría idempotentes. [`legacy-invitation-binding-upgrade.live.test.ts`](../packages/database/test/legacy-invitation-binding-upgrade.live.test.ts) cubre aceptación exacta, rollback ambiguo, rama `initial_admin` y compatibilidad desde head 034. La aceptación revalida todo dentro de la transacción. `password_provisioned=false` acompaña un hash Argon2id sin preimagen; si password se exige, `INVITATION_PASSWORD_REQUIRED` ocurre antes de mutar.

El store fija `device_type` y WebAuthn BE como propiedades inmutables, rechaza su cambio entre ceremonias y no admite Backup State verdadero con BE falso; la base exige equivalencia `multiDevice`/BE y UV se evalúa en cada assertion. El reemplazo liga la credencial anterior a la ceremonia, mantiene esa passkey activa hasta verificar la nueva y hace alta/revocación dentro de una única transacción. La sesión resultante de invitación sólo se emite como cookie `HttpOnly`, queda ligada a la invitación con assurance `enrollment_only`, cero permisos operativos y un máximo de diez minutos.

La cobertura específica de los nuevos límites está en [`invitation-password-upgrade.live.test.ts`](../packages/database/test/invitation-password-upgrade.live.test.ts), [`atomic-authentication-context-contract.test.ts`](../packages/database/test/atomic-authentication-context-contract.test.ts), [`invitation-role-delegation-contract.test.ts`](../packages/database/test/invitation-role-delegation-contract.test.ts), [`invitation-grantor-revocation-contract.test.ts`](../packages/database/test/invitation-grantor-revocation-contract.test.ts) y [`access-control.live.test.ts`](../packages/database/test/access-control.live.test.ts). Esas pruebas quedaron incluidas en las 441/441 pruebas DB del cierre vigente.

La confianza de proxy también cambió de implícita a explícita: [`config.ts`](../apps/api/src/config.ts) valida `API_TRUSTED_PROXY_CIDRS`, exige una allowlist no vacía en producción y rechaza wildcard; [`server.ts`](../apps/api/src/server.ts) desactiva forwarding headers cuando no hay lista. [`contracts.test.ts`](../apps/api/test/contracts.test.ts) y [`trusted-proxy.test.ts`](../apps/api/test/trusted-proxy.test.ts) contienen los contratos de configuración, cadena de proxies y rate limiting frente a headers falsificados. En web, [`proxy.ts`](../apps/web/proxy.ts) redirige 307 las autoridades loopback-IP de puertos operativos hacia destinos `localhost` fijos, preserva ruta/query, usa `no-store`, no emite cookies y nunca deriva el destino de `Host`/`X-Forwarded-Host`. Los endpoints que emiten cookie requieren `Origin` canónico; el gate [`assert-browser-origin-bundle.mjs`](../apps/web/scripts/assert-browser-origin-bundle.mjs) impide hornear `127.0.0.1:4000` en chunks del navegador. Listeners y `/healthz` siguen en 127.

La cobertura UI de teléfono/PC conserva passkey como camino principal y TOTP como fallback mediante deep link `otpauth:` same-phone, QR local y clave manual. La aceptación adaptativa sólo revela contraseña tras `INVITATION_PASSWORD_REQUIRED`. El AppShell excluye `recovery_limited` del cálculo de redirect y, junto con `enrollment_only`, renderiza el Centro de seguridad requerido sin bucle de navegación.

Estas referencias prueban trazabilidad de implementación; el `pnpm verify:local` vigente aporta el resultado integral ejecutado, los conteos, la huella fuente, supply-chain/audit, estado persistente, artefactos de reporte y salud terminal. Ese cierre acredita únicamente el laboratorio local descrito y no concede certificación institucional o de producción.

El script [`scripts/verify-local.ps1`](../scripts/verify-local.ps1) primero exige API saludable y el archivo local de acceso Demo; luego fija `NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true` y ejecuta:

1. `pnpm security:supply-chain`;
2. `pnpm audit --prod --audit-level high` contra la asesoría vigente de npm;
3. `pnpm typecheck`;
4. `pnpm lint`;
5. reconstrucción y reinicio de API, worker y web desde el código exacto bajo prueba;
6. las suites de contrato, dominio, E2EE, base de datos, API live y web unit por separado; la etapa DB usa la exclusión explícita de cierre para `seed-audit-history.live.test.ts`;
7. `pnpm test:e2e`, salvo uso explícito de `-SkipE2E`.

Una dependencia live ausente produce fallo: el target integral no convierte silenciosamente una prueba PostgreSQL en `skip`.

La ruta de contenedores no forma parte de la evidencia runtime de este host porque Docker CLI/Engine no está disponible. Sus Dockerfiles, Compose y contratos se inspeccionan estáticamente; build, arranque y healthchecks reales requieren otro host con Docker.

## Evidencia del pase integral vigente

El artefacto final registró estas ejecuciones dentro del mismo pase controlado:

| Capa | Evidencia observada | Alcance y precisión |
|---|---|---|
| Toolchain | typecheck, lint y build: `PASS` | pase integral final con source-integrity igual al inicio, final y publicación |
| Contrato del verificador | 39/39 en 3 archivos | publicación fail-closed, parsers, motores, skips, scanner e integridad de fuente |
| TypeScript | 7/7 paquetes con typecheck correcto | dominio, catálogo, i18n, E2EE, datos, API y web |
| Dominio | 41/41 en 4 archivos | estados, permisos, propuestas, votos, desempates, métricas, elegibilidad y fixture |
| E2EE | 31/31 en 2 archivos | HPKE multi-destinatario, AAD/replay, validación de boleta, recuento, firmas y recuperación |
| Base | 441/441 en 80 archivos, 0 omitidas | integración live obligatoria sobre PostgreSQL 18 loopback |
| API | 417/417 en 58 archivos, 0 omitidas | contratos, rutas, guardas real-stack e integración PostgreSQL live del corte probado |
| Web unit | 227/227 en 40 archivos, 0 omitidas | checks unitarios y contractuales del corte probado |
| Total no-Playwright | 1.196/1.196, 0 omitidas | suma exacta de verificador, dominio, E2EE, base, API y web |
| Playwright | 160 resultados: 106 aprobados, 54 skips exactos revisados, 0 fallos | cuatro proyectos efectivos; cada skip coincidió con la allowlist y no se contabiliza como aprobado |
| OpenAPI | 149 paths, 165 operaciones y 278 esquemas | sintaxis, referencias y paridad del contrato fuente vigente |
| I18n | 2.404 claves por locale, paridad exacta ES/EN/FR | comprobación estructural; revisión lingüística institucional externa |

Pruebas live adicionales cubren invitaciones, activación, MFA, importación, aislamiento tenant, control global, aprovisionamiento, fotos, custodia, ciclo de claves, flujo institucional y almacenamiento de reportes. La [Matriz de aceptación](acceptance-matrix.md) evita extrapolar esa cobertura a propiedades no ensayadas. Para comparación, los conteos 887 no-Playwright y 124 Playwright pertenecen exclusivamente al corte del 13-09 preservado en el [artefacto histórico por SHA-256](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json).

## PostgreSQL y datos

- El toolchain usa binarios PostgreSQL 18.6; el verificador confirmó servidor major 18 en el clúster aislado del proyecto, únicamente en `127.0.0.1:55432`.
- El chequeo persistente de solo lectura incluido en el pase vigente confirmó control 26/26 con cabeza `026_invitation_enrollment_recovery_qualification.sql` y Demo/Ozama 38/38 con cabeza tenant `036_transactional_invitation_grantor_lock.sql`; terminó `pass=true`, `mismatchCount=0`, sin pendientes, migraciones inesperadas, checksums divergentes, drift de esquema, desajustes de rutas/roles ni backlog de workers.
- Demo y Ozama usan bases, roles de ejecución y referencias de secreto distintas.
- Demo confirmó 180 miembros y 150 elegibles, con 0 desajustes de inventario, ownership o grants runtime. Ozama confirmó 47 tablas operativas, 0 filas y también 0 desajustes de inventario, ownership o grants runtime. La comprobación vigente repitió esos invariantes con `pass=true` y `mismatchCount=0`. Ambos tenants contienen la revisión canónica `2025.1.0`: 29 departamentos, 67 cargos y digest `sha256:c41426801200251a88b90c8d3dfc6f3f158332c3158e77adf1b4bd72e90c6fb8`.
- El seed y los flujos mutables apuntan a la allowlist Demo; Ozama no recibió datos sintéticos durante backup, drill ni upgrade.
- El fixture fuente de Demo define 180 miembros y 150 elegibles. Ese contrato no demuestra por sí solo el estado de la base persistente, que se valida por separado.
- El acceso Demo v2 define identidades separadas para administración, secretaría, integrante de comisión, custodia y auditoría, cada una con contraseña y TOTP propios; el alias superior conserva compatibilidad con el administrador predeterminado sin publicar ningún secreto.

No se publican nombres de base, URLs, contraseñas, tokens, URI TOTP ni claves.

## OpenAPI

[`api/openapi.json`](api/openapi.json) es OpenAPI 3.1 y su censo estructural fuente vigente es **149 paths, 165 operaciones y 278 esquemas**. Incluye ceremonias de registro/login/step-up WebAuthn, política de identidad, passkeys y sesiones, además de cualificaciones y la corrección inmutable `POST /v1/reports/{reportId}/corrections`. El pase integral vigente validó sintaxis, referencias y paridad de esta fuente. El censo 129/142/235 pertenece exclusivamente al [corte histórico del 13-09](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json).

La paridad automatizada no sustituye:

- validación semántica por una segunda implementación OpenAPI;
- pruebas exhaustivas de cada variante de respuesta;
- generación/compilación de clientes externos;
- compatibilidad de versiones publicada.

## Navegador

La configuración Playwright define hasta cinco proyectos; el preflight decide si el binario nativo de Firefox puede incorporarse al pase efectivo:

| Proyecto | Motor / viewport / locale |
|---|---|
| `desktop-chromium-es` | Chromium, 1440×900, es-DO |
| `desktop-firefox-en` | Firefox, 1280×800, en-US; condicional al preflight nativo |
| `mobile-chromium-es` | Chromium táctil, 412×915, es-DO |
| `mobile-webkit-fr` | WebKit táctil, 390×844, fr-FR |
| `mobile-small` | Chromium táctil, 320×568, es-DO |

El pase integral vigente registró **160 resultados** sobre cuatro proyectos efectivos: `desktop-chromium-es` 40/40; `mobile-chromium-es`, `mobile-small` y `mobile-webkit-fr`, cada uno con 22 aprobados y 18 skips revisados. En total fueron 106 aprobados, 54 skips exactos y 0 fallos. El probe confirmó Chromium y WebKit disponibles; Firefox siguió opcional y no inició en ese host (`WINDOWS_NATIVE_SPAWN_UNKNOWN`). Algunas mutaciones se ejecutan deliberadamente una sola vez en Chromium y se omiten en los demás proyectos; cada una de las 54 omisiones coincidió exactamente con la allowlist publicada. El redirect canónico desde loopback-IP, incluida la preservación de ruta/query/fragmento y la llegada al origen `localhost`, aprobó en los cuatro perfiles. El corte previo de 124 resultados se conserva únicamente en el [artefacto histórico por SHA-256](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json).

La inspección interactiva complementaria recorrió login, invitación y bootstrap en ES/EN/FR. Detectó un overflow real del bootstrap a 320 px, que se corrigió con sizing de borde, ancho mínimo cero y wrapping de acciones; la repetición sobre la compilación productiva dejó `scrollWidth=305` frente a viewport 320, botones de 48–56 px, controles habilitados después de hidratación y cero overflow en las seis combinaciones idioma/formulario. También confirmó foco visible por teclado, error de login sintético localizado sin bucle y manifiestos PWA localizados con HTTP 200. Esta inspección automatizada asistida no se presenta como certificación humana con tecnologías de apoyo.

La evidencia existente bajo [`docs/evidence`](evidence/) incluye acceso móvil, resumen autenticado, recibo móvil y un ejemplo PDF/XLSX/CSV. Esos artefactos contienen solo datos sintéticos y deben considerarse evidencia del pase que los generó, no de cambios posteriores. Playwright desactiva trazas, video y capturas automáticas para no conservar secretos en formularios.

## Real-stack dedicado de flujos críticos

Los preflights read-only anteriores se conservan como cortes históricos separados en [`real-browser-stack-preflight.sha256-736e6c338615005d917f7c0104c713f3fe2786e79cb5cf4450847d705f71bbaa.json`](../artifacts/history/real-browser-stack-preflight.sha256-736e6c338615005d917f7c0104c713f3fe2786e79cb5cf4450847d705f71bbaa.json) y [`real-browser-stack-preflight.sha256-2d44a96595513067007bd64c1798ae2c999bb34c7a7888d073d89e675d93911e.json`](../artifacts/history/real-browser-stack-preflight.sha256-2d44a96595513067007bd64c1798ae2c999bb34c7a7888d073d89e675d93911e.json). No se atribuyen al run vigente ni sustituyen sus comprobaciones antes/después.

La ejecución expresamente autorizada vigente [`artifacts/real-browser-stack-local.json`](../artifacts/real-browser-stack-local.json) pasó entre `2026-09-14T10:55:31.681Z` y `2026-09-14T10:55:43.495Z`; el artefacto mide 3.953 bytes y tiene SHA-256 `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`. Sus 4/4 pruebas comprobaron una ceremonia passkey Chromium real con autenticador virtual CTAP2 interno, credencial residente y verificación de usuario —alta, AAL2 phishing-resistant, logout/login, rechazo de replay, step-up exacto de un uso y revocación—; reportes PDF/XLSX/CSV generados, cifrados, persistidos, recuperados y descargados; importación preview/commit con reintentos idempotentes y homónimo; y boleta/abstención, recibos y escrutinio con dos custodios. Registró `scenarioPass=true`, `cleanupPass=true`, `protectedDatabasesUnchanged=true`, cero bases/roles efímeros residuales, cero huérfanos globales y `reservedPortsUsedByScenario=false`; las huellas de control, Demo y Ozama y el digest global del clúster fueron exactos antes/después. La observación sanitizada no publica secretos, challenges ni material privado.

## Reportes

Las pruebas unitarias y contractuales verifican:

- los trece tipos y sus audiencias permitidas;
- filtros aplicables por tipo y ausencia de dependencias de datos no autorizadas;
- instantánea/filtros y AAD exactos;
- transición `pending → ready/failed`, descarga histórica y evento de impresión;
- corrección mediante una nueva emisión, supersesión lineal inmutable, única sucesora, razón normalizada y navegación de revisiones sin sobrescribir el original;
- validación de hashes, tamaños, manifiesto y contexto antes de descifrar;
- PDF paginado con subconjuntos estáticos de Bitstream Vera Sans embebidos, XLSX sin fórmulas y CSV UTF-8/BOM neutralizado.

El recorrido Playwright conservado analiza un PDF con `pdf-lib`, un XLSX con ExcelJS y el CSV; no solo comprueba tamaño. Además, `verify:local` exige renderizar el PDF generado con Poppler (`pdftoppm`) y falla ante errores del renderer o diagnósticos de sintaxis/fuentes. Aun así, no existe evaluación manual de PDF etiquetado, orden de lectura o compatibilidad con lectores de pantalla.

## Carga AC-37

El artefacto [`performance-scale-local.json`](../artifacts/performance-scale-local.json), esquema 3, registra una ejecución de **24,635 s**, desde `2026-09-13T03:16:20.875Z` hasta `2026-09-13T03:16:45.510Z`, con `overallPass: true`:

- 10 tenants efímeros × 50 participantes × 10.000 miembros = 100.000 miembros;
- 500 mutaciones HTTP, p95 **1.288,811 ms**, bajo presupuesto exclusivo `< 1.500 ms`;
- 500 eventos SSE, p95 **990,481 ms**, bajo presupuesto exclusivo `< 2.000 ms`;
- 1.000 lecturas bajo 500 sesiones, p95 combinado **866,517 ms**, bajo presupuesto exclusivo `< 2.000 ms`;
- listado contra 10.000 miembros, p95 **714,602 ms**;
- 10/10 cruces de credencial DB denegados, 10/10 tenant IDs foráneos denegados y 10/10 rondas foráneas ocultas;
- huellas completas de control, Demo y Ozama iguales antes/después, inventario global del clúster igual y cero bases/roles efímeros huérfanos; huella del control: `sha256:71ebf60379863c758405548af410982b9c2ca7bb3bb7d39fabede41763f9dc08`.

El runner usó HTTP/SSE loopback sin TLS, proxy, WAN ni escalamiento horizontal. Esa prueba de servidor no mide por sí sola experiencia de navegador; el ensayo separado siguiente cubre esa parte bajo condiciones de laboratorio.

## Rendimiento de navegador local

El artefacto [`performance-browser-local.json`](../artifacts/performance-browser-local.json) registra una ejecución Chromium separada, completamente sintética y en memoria, con `overallPass: true`:

- 10.000 sobres AES-256-GCM y 4.547.671 bytes transferidos por HTTP loopback;
- descarga 12,9 ms, parse 8,3 ms, descifrado 128,9 ms, índice 19,3 ms y pipeline descarga/descifrado/índice 322,7 ms;
- búsqueda local p95 4,0 ms y máximo 4,5 ms;
- procesamiento en Web Worker con brecha máxima de frame de 16,7 ms;
- página pública de acceso bajo emulación móvil: LCP 160 ms, CLS 0 e INP de laboratorio 16 ms.

Los valores prueban el runner y sus umbrales inclusivos en ese equipo. El propio artefacto declara que no ejercita la ruta ni componentes reales de Members, API operativa o PostgreSQL; las métricas web pertenecen a `/es/auth/sign-in` sin autenticación. No modelan WAN, jitter, pérdida, TLS ni proxy; la emulación móvil Chromium no es hardware físico, y un INP de una ejecución de laboratorio no es un percentil RUM/field Core Web Vitals.

## Backup y auditoría

Un ensayo local anterior documentado en [`packages/database/BACKUP.md`](../packages/database/BACKUP.md) creó un backup autenticado de Demo, restauró y verificó filas/invariantes en una base scratch y limpió el scratch. Registró 0,922 s como edad conservadora del punto de recuperación y 0,675 s para restauración/verificación/limpieza. Es evidencia histórica del dataset sintético local, no del runner/política actuales ni de RPO/RTO productivo.

El cierre del 13-09-2026 creó backups cifrados nuevos después del QA y ejecutó drills con directorio explícito. Demo produjo 1.668.147 bytes cifrados en 441 ms; su restauración tomó 1.049 ms, cumplió RPO/RTO, eliminó `nom_restore_d0000000_b7fb4134` y confirmó a Ozama como único vecino sin cambios. Ozama produjo 297.591 bytes cifrados en 384 ms; su restauración tomó 956 ms, cumplió RPO/RTO, eliminó `nom_restore_0a2a0000_a73ab5e6` y confirmó a Demo como único vecino sin cambios.

El inventario Ed25519 fue revalidado después del real-stack y del verify definitivo. El checkpoint vigente terminó `completed` sobre 1.274 eventos Demo y dejó 5 checkpoints/anclas, con secuencia 5. `verify` pasó; el drill aislado detectó los cinco casos esperados —alteración, borrado intermedio, truncamiento, reordenamiento y rollback—, registró `databaseWrites=0` y eliminó las copias temporales. El ledger está en el mismo host: demuestra detección frente a una cabeza conservada, pero no constituye WORM ni separación administrativa.

> **CIERRE_CONTINUIDAD_FINAL: APROBADO EN LABORATORIO EN SU CORTE HISTÓRICO.** La salida sanitizada de backups, drills y reinicio está en [`artifacts/continuity-restart-final.json`](../artifacts/continuity-restart-final.json) y conserva correctamente su corte de 921 eventos/secuencia 2. El postcheck histórico agregó por separado el corte 1.274/5. Las cinco muestras de salud de aquel corte confirmaron API HTTP, web HTTP y worker verdes; la última, a `2026-09-13T20:31:46.3584053Z`, observó heartbeat del worker en `20:31:46.093Z`.

El postcheck histórico queda preservado por separado en [`artifacts/closure-postcheck-final.json`](../artifacts/closure-postcheck-final.json). Es una agregación sanitizada de resultados observados, no una atestación firmada ni evidencia del alias `verify-local-final.json` vigente; el artefacto histórico de continuidad no se reescribe para aparentar que contiene un corte posterior.

## Cadena de suministro vigente

El pase integral vigente ejecutó `security:supply-chain`, audit de dependencias productivas y scanner de entrega sobre la fuente/lockfile actuales. El scan de fuente inspeccionó **698 archivos** —695 de texto y 3 binarios— sin hallazgos según su política. Los artefactos vigentes contienen:

- SBOM CycloneDX 1.6 con 731 componentes;
- inventario de licencia correspondiente, sujeto a revisión jurídica humana;
- SHA-256 de `pnpm-lock.yaml`: `76f79becff711e1e30ffbb212a76892363208f1f726b6d3b5a6ff39308897e96`.

`pnpm audit --prod --audit-level high` terminó sin vulnerabilidades conocidas en la consulta puntual incluida en el pase vigente y el delivery scan aprobó. Estos controles no prueban ausencia futura de vulnerabilidades ni sustituyen revisión de código, procedencia, licencias o activos. Los conteos 1.003/686 y la huella de lockfile anterior del 13-09 sólo son reproducibles desde el [artefacto histórico por SHA-256](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json).

## Evidencia externa que sigue pendiente

- validación denominacional y territorial de Ozama;
- privacidad, base jurídica, residencia, retención y proveedores;
- permisos/traducciones de marca y manuales;
- revisión criptográfica, seguridad y pentest independientes;
- lectores de pantalla, teclado completo, zoom 400 % y dispositivos físicos;
- KMS/HSM, correo, objetos, TLS, observabilidad, backups fuera del host y WORM real;
- dominio RP definitivo, DNS/HSTS, IdP/SCIM y FIDO MDS/attestation si se pretende AAL3;
- pruebas físicas de passkeys y recuperación en iOS, Android, Windows y macOS;
- revisión jurídica humana de licencias, avisos y activos del bundle final.
