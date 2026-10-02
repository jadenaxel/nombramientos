# Nombramientos Adventistas

Aplicación web local para apoyar el proceso de una junta de nombramientos sin confundir propuesta, recomendación, consentimiento, presentación y elección por la iglesia. La entrega integra web, API, worker y PostgreSQL. En el despliegue de GestionChurch funciona como un módulo federado: reutiliza la sesión, el tenant y los roles de GestionChurch, sin segundo login ni MFA propio.

## Integración con GestionChurch

El modo integrado es el modo operativo de esta instalación. Se inicia desde `X:\CODE\GestionChurch\start-gestionchurch.ps1` y expone Web en `http://localhost:3300`, API en `http://localhost:4100` y un worker durable con health obligatorio. El usuario siempre entra por `http://localhost:3000/login` y abre **Nombramientos** desde el menú de GestionChurch.

- `GLOBAL_ADMIN`, `TENANT_ADMIN` y `BOARD_SECRETARY` reciben acceso automáticamente.
- `NOMINATIONS_USER` permite conceder acceso a otros usuarios desde GestionChurch.
- `GLOBAL_ADMIN` se proyecta sobre el tenant que seleccione; cualquier identidad tenant queda físicamente limitada a su propia iglesia.
- Los códigos de lanzamiento duran 60 segundos, son de un solo uso y sólo se canjean servidor a servidor.
- Cada solicitud autenticada revalida en vivo que la cuenta, el tenant y la huella de roles continúen autorizados; una revocación en GestionChurch invalida la sesión del módulo.
- El login, bootstrap, invitaciones y MFA propios de Nombramientos no se registran en modo integrado. El 2FA se incorporará más adelante como una capacidad transversal de GestionChurch.
- El PostgreSQL compartido sigue usando una base física por tenant de Nombramientos y credenciales runtime separadas. No se instaló otro PostgreSQL.

Para preparar o inspeccionar sólo el módulo:

```powershell
.\scripts\gestionchurch-module.ps1 -Action Prepare
.\scripts\gestionchurch-module.ps1 -Action Status
```

## Estado de la entrega

El alcance ejecutable del laboratorio está implementado de extremo a extremo: passkeys/WebAuthn como método primario, TOTP como fallback configurable, recuperación restringida, step-up ligado a la operación, sesiones y credenciales revocables, políticas de identidad por tenant, permisos locales, padrón cifrado, importación, fotografías normalizadas/cifradas, comité, ciclos y sesiones, propuestas, revisión, boletas con custodia, escrutinio, asignaciones, reportes, auditoría, backups y restauración aislada. El Centro de seguridad permite a la administración autorizada configurar métodos de acceso y límites de sesión además de las metas de assurance; mantiene visibles pero no editables los pisos criptográficos de verificación de usuario/resistencia al phishing y la matriz de requisitos por acción. La operación de autenticación se documenta en [Autenticación enterprise](docs/authentication.md).

El producto **no está autorizado para producción ni para datos reales de Ozama**. El código y las pruebas locales no sustituyen aprobación eclesiástica, asesoría jurídica, evaluación WCAG, auditoría criptográfica o pentest. Consulte [Limitaciones conocidas](docs/known-limitations.md) y la [Matriz de aceptación](docs/acceptance-matrix.md).

> **CIERRE LOCAL INTEGRAL ACTUAL: APROBADO.** El alias mutable [`artifacts/verify-local-final.json`](artifacts/verify-local-final.json) registra la ejecución UTC de `2026-09-14T10:56:10.4065404Z` a `11:04:21.4060919Z`: `result=passed`, `overallPass=true`, `closureEligible=true`, 26 etapas —25 aprobadas y el probe Firefox aceptado como opcional—. Pasaron 1.196/1.196 pruebas no-Playwright —verificador 39/39, dominio 41/41, E2EE 31/31, base 441/441, API 417/417 y web 227/227—; Playwright cerró 106 aprobadas + 54 omisiones exactas allowlisted = 160 planificadas, con 0 fallos. Chromium y WebKit fueron obligatorios y quedaron verdes en los cuatro perfiles; Firefox no estuvo disponible en este Windows nativo y se registró como opcional con salida 2. El artefacto mide 41.090 bytes, tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6` y ata inicio, fin y publicación a la misma huella de 654 archivos fuente: `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f`.

> **EVIDENCIA HISTÓRICA, NO ACTUAL.** El pase integral del 13-09 se conserva de forma content-addressed en [`artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json`](artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json). Sus 887/887 pruebas no-Playwright, 70 aprobadas + 54 omisiones Playwright y SHA-256 `532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a` describen únicamente aquella huella anterior. [`artifacts/closure-postcheck-final.json`](artifacts/closure-postcheck-final.json) es también un suplemento histórico ligado a evidencia anterior; no sustituye ni amplía el cierre actual.

> **CIERRE_CONTINUIDAD_FINAL: APROBADO EN LABORATORIO.** Backups cifrados y restore drills aislados de Demo y Ozama pasaron simétricamente, conservaron al tenant vecino, cumplieron RPO/RTO y eliminaron sus bases scratch. La verificación local más reciente del anclaje Ed25519 de Demo alcanzó 1.274 eventos, 5 checkpoints/anclas y secuencia 5; `verify` pasó y el drill detectó 5/5 manipulaciones con `databaseWrites=0`. El artefacto [`continuity/restart histórico`](artifacts/continuity-restart-final.json) conserva correctamente la fotografía anterior de 921 eventos y secuencia 2; no representa la cabeza actual. Los anclajes locales emulan detección y no constituyen WORM productivo.

> **REAL-STACK ACTUAL: APROBADO.** La ejecución autorizada `pnpm test:e2e:real-stack:local` de `2026-09-14T10:55:31.681Z` a `10:55:43.495Z` aprobó 4/4 pruebas sobre API, Chromium y PostgreSQL efímeros reales: passkey residente con verificación de usuario —alta, AAL2, logout/login, rechazo de replay, step-up de un uso y revocación—, reportes PDF/XLSX/CSV persistidos y descargados, importación idempotente con homónimo, y boleta/abstención/escrutinio con dos custodios. `scenarioPass`, `cleanupPass` y `protectedDatabasesUnchanged` quedaron en `true`; las huellas protegidas no cambiaron y el cleanup confirmó cero bases y roles efímeros. [`artifacts/real-browser-stack-local.json`](artifacts/real-browser-stack-local.json) mide 3.953 bytes y tiene SHA-256 `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`.

> **ESTADO FUENTE/PERSISTENTE ACTUAL: RECONCILIADO.** La verificación integrada confirmó `mismatchCount=0`: control 29/29 con cabeza `029_gestionchurch_federation_generated_column_fix.sql`; tenants 39/39 con cabeza `037_gestionchurch_federation.sql`; Demo conserva 180 miembros/150 elegibles y Ozama está activo y enlazado al tenant correspondiente de GestionChurch. Los registros federados autorizados se distinguen de artefactos locales prohibidos y el verificador continúa fallando ante drift de esquema, grants, rutas o aislamiento.

## Componentes conectados

- Next.js 16 y React 19, interfaz adaptable y rutas ES/EN/FR; los catálogos fuente mantienen paridad exacta de 2.404 claves por locale. Passkey es el camino principal tanto en teléfono como en PC; TOTP ofrece enlace `otpauth:` en el mismo teléfono, QR local desde PC y clave manual accesible. El AppShell mantiene `enrollment_only` y `recovery_limited` dentro del Centro de seguridad, sin rebotar entre la ruta destino y el gate. El cierre actual aprobó 227/227 pruebas unitarias web y una matriz Playwright de 160 resultados —106 aprobados, 54 omisiones exactas gobernadas y 0 fallos—; Chromium y WebKit obligatorios quedaron verdes. Esto no sustituye una evaluación WCAG humana ni pruebas físicas.
- Fastify 5 bajo `/v1`, cookies `HttpOnly`, CSRF, rate limiting, idempotencia, passkeys/WebAuthn, TOTP, recuperación restringida y step-up transaccional. La creación de sesiones bloquea en un orden común la policy y el contexto activo identidad/membresía/tenant, relee los límites y confirma en una sola transacción; los cambios de policy validan readiness de todo el tenant, reconcilian sesiones e invalidan/contabilizan WebAuthn, TOTP y grants anteriores. El tipo de dispositivo y el bit WebAuthn BE quedan fijados al registrar la credencial; un assertion posterior no puede cambiarlos, `backup_state=true` nunca es válido con BE falso y UV se evalúa en cada uso. Reemplazar una passkey mantiene la anterior activa hasta verificar la nueva y efectúa alta/revocación en una sola transacción. Cada challenge MFA admite como máximo seis reservas atómicas de intento. Los fallos de contraseña y MFA comparten además un presupuesto fijo por identidad de 8 intentos/15 minutos que no desplaza su vencimiento durante el bloqueo, y los cambios de tenant comprueban/clampan la sesión contra la política destino antes y durante la rotación. Las invitaciones exigen `role.manage` y una arista explícita en una matriz DB read-only de roles de sistema; esa autoridad se bloquea/revalida al aceptar y toda invitación abierta se revoca al desactivar grantor, membresía o tenant. Una invitación passwordless crea `password_provisioned=false`, no una contraseña latente, emite sólo una sesión cookie `enrollment_only` ligada a la invitación y la remediación histórica destruye credenciales 019-era únicamente cuando la policy de aceptación puede probarse sin ambigüedad. El archivo OpenAPI 3.1 fuente actual contiene 149 paths, 165 operaciones y 278 esquemas.
- Los encabezados reenviados están deshabilitados salvo que el peer inmediato pertenezca a la allowlist explícita `API_TRUSTED_PROXY_CIDRS`; producción falla al arrancar si esa lista está vacía y rechaza confianza wildcard. La topología de proxy/TLS productiva y su pentest continúan siendo dependencias externas.
- PostgreSQL 18 aislado en `127.0.0.1:55432`, con plano de control y una base/rol/credencial de ejecución por tenant. Fuente y estado persistente están en 29 migraciones control hasta `029_gestionchurch_federation_generated_column_fix.sql` y 39 archivos tenant hasta `037_gestionchurch_federation.sql`; el verificador confirma checksums, ownership, grants, catálogo y aislamiento. Las migraciones 027–029 y 037 añaden el enlace federado, la identidad sintética sin contraseña utilizable y la sincronización exacta de roles.
- El origen de navegador local es `http://localhost:3000` y su API visible es `http://localhost:4000`; listeners y healthchecks permanecen en `127.0.0.1`. Las autoridades loopback-IP de puertos operativos conocidos reciben un 307 absoluto server-side hacia un destino `localhost` fijo, preservando path/query; el navegador conserva también el fragmento original. La respuesta usa `Cache-Control: no-store`, no emite `Set-Cookie` y nunca deriva el destino de `Host`/`X-Forwarded-Host`; `/healthz` no se redirige. Los cuatro perfiles Playwright comprobaron este contrato, incluidas cabeceras reenviadas hostiles y disponibilidad posterior de passkey. Los endpoints que emiten cookies exigen un `Origin` canónico y el build falla si un bundle de navegador contiene la API `127.0.0.1:4000` o no contiene la referencia canónica.
- Catálogo canónico con revisión de contenido `2025.1.0`, 29 departamentos y 67 oficinas/cargos. El paquete institucional conserva estado `draft`: su aprobación denominacional y regional continúa pendiente y externa.
- Worker durable de aprovisionamiento, separado del proceso API y de sus credenciales ordinarias.
- Cifrado de contenido en navegador, ciclo de claves por dispositivo y sobres HPKE multi-custodio para boletas.
- Importación de hasta 10.000 miembros procesada en un Web Worker, con transferencia binaria, preview y decisiones antes del commit para mantener responsiva la interfaz.
- Trece tipos de reporte —doce institucionales y un resumen operativo— en PDF/XLSX/CSV, con artefactos cifrados, ciclo `pending → ready/failed` y correcciones por supersesión lineal inmutable.
- Analítica operativa con período, fase, filtros, denominadores, versión de ronda y timestamp derivado de mutaciones persistidas; los estados anulados no contaminan el dashboard.
- Backups tenant cifrados y ensayo de restauración en una base scratch; checkpoints/anclajes firmados como emulación local de detección, no WORM real.
- Rendimiento de escala verificado sobre 10 tenants efímeros y 100.000 miembros. La medición Chromium complementaria usa un dataset sintético en memoria y la página pública de acceso: no mide la ruta, componentes, API ni PostgreSQL reales de Members.
- El cierre actual regeneró SBOM, inventario de licencias, audit y escaneos de fuente/entrega sobre la huella congelada; que esas etapas sean verdes es evidencia del alcance automatizado declarado, no firma SLSA, revisión jurídica ni garantía de ausencia absoluta de vulnerabilidades o secretos.

## Requisitos locales

- Windows 10/11 o Windows Server con PowerShell.
- Node.js 24 y pnpm 11.19.0.
- PostgreSQL 18 en `C:\Program Files\PostgreSQL\18\bin`, o ruta explícita aceptada por los scripts.
- Chromium y WebKit de Playwright son obligatorios para el cierre local. Firefox integra la matriz cuando su binario nativo supera el preflight; cualquier exclusión queda explícita en la evidencia.

El clúster del proyecto no registra ni modifica el servicio PostgreSQL del sistema. Los scripts rechazan host no-loopback y el puerto estándar `5432`; este workspace usa únicamente el puerto local `55432`.

Como alternativa reproducible y aislada, la ruta Docker Compose define PostgreSQL 18, bootstrap/migraciones, API, web, worker y healthchecks sin relajar ese contrato ni reutilizar los puertos Windows. Sus contratos tienen validación estática; este equipo no dispone de Docker CLI/Engine y, por tanto, todavía no aporta evidencia de build o ejecución de contenedores. Véase [Desarrollo reproducible con contenedores](docs/container-development.md).

## Preparación y arranque

Desde la raíz:

```powershell
pnpm bootstrap:local
pnpm start:local
```

Abra `http://localhost:3000/es/auth/sign-in`. `localhost` es el origen canónico requerido para probar passkeys/WebAuthn; una entrada por los puertos operativos de `127.0.0.1` o `::1` se redirige en el servidor antes de mostrar autenticación.

El bootstrap genera secretos aleatorios sin imprimirlos. Los cinco accesos Demo independientes —administración, secretaría, integrante de comisión, custodia y auditoría— tienen contraseña y URI TOTP propias y quedan exclusivamente en `packages/database/.local/demo-access.json`; su formato v2 conserva como alias compatible el perfil administrador predeterminado. La activación inicial global, cuando hace falta, queda en `packages/database/.local/platform-admin-bootstrap.json`. Ambos archivos son secretos locales ignorados por Git y protegidos por ACL. No los copie a tickets, capturas, documentación o logs.

Para detener todo:

```powershell
pnpm stop:local
```

Para detener web/API/worker y conservar PostgreSQL activo:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop-local.ps1 -KeepDatabase
```

## Verificación

Con la pila saludable:

```powershell
pnpm verify:local
```

El target exige las precondiciones live y ejecuta cadena de suministro, typecheck, lint, dominio, E2EE, base, API, pruebas unitarias web y Playwright. Si API, PostgreSQL o las credenciales locales faltan, falla en vez de omitir silenciosamente la integración.

Comandos útiles:

```powershell
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm test:e2e
pnpm db:status
pnpm security:supply-chain
pnpm audit --prod --audit-level high
pnpm performance:scale:local
pnpm performance:browser:local
```

Backups y continuidad local:

```powershell
# Sólo durante la configuración inicial, cuando no exista inventario de claves:
pnpm --filter @nombramientos/database db:backup:configure

# Operación rutinaria con el inventario existente:
pnpm --filter @nombramientos/database db:backup:demo
pnpm --filter @nombramientos/database db:restore:drill:demo
```

Los procedimientos y guardas están en [Operación](docs/operations.md). Los resultados de carga están en [Rendimiento](docs/performance.md).

## Datos reales y dependencias externas

Antes de cargar datos reales se requiere, como mínimo:

1. confirmar jurisdicción, suplementos y procedimiento denominacional aplicable a Ozama;
2. aprobar base jurídica, residencia, retención, derechos y tratamiento de fotografías/datos religiosos;
3. revisar traducciones, marca y permisos de manuales/activos;
4. completar auditoría criptográfica, revisión de seguridad y pentest independientes;
5. completar pruebas humanas con lectores de pantalla, teclado, zoom y dispositivos reales;
6. fijar el dominio RP WebAuthn definitivo y desplegar DNS, TLS/HSTS, una allowlist exacta de CIDR/IP para el reverse proxy, KMS/HSM, correo, objetos, backups externos, observabilidad y WORM real;
7. integrar IdP/SCIM y FIDO Metadata Service/attestation si la política institucional exige autenticadores administrados o AAL3;
8. completar pruebas físicas iOS/Android/Windows/macOS y la revisión jurídica humana de licencias, avisos y activos del bundle final.

## Estructura

- `apps/web`: interfaz, cifrado/descifrado local, reportes y pruebas Playwright.
- `apps/api`: API, autenticación, autorización, SSE y contrato OpenAPI.
- `packages/database`: migraciones, stores, tenant isolation, worker, backup y auditoría local.
- `packages/domain`: estados, permisos, reglas y métricas deterministas.
- `packages/e2ee`: HPKE, recuento local, atestaciones y ciclo de claves.
- `packages/catalog` / `packages/i18n`: catálogo versionado y textos ES/EN/FR.
- `docs`: decisiones, operación, seguridad, evidencia y límites.
- `artifacts`: SBOM, inventario de licencias y evidencia sanitizada de verify integral, real-stack, continuidad, reinicio y rendimiento.
