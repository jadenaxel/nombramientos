# Operación y continuidad local

Fecha de corte: **14 de septiembre de 2026**.

## Alcance

Este runbook opera la edición local de desarrollo. Implementa bootstrap, migraciones, aprovisionamiento, seed Demo, worker, arranque supervisado, passkeys/TOTP/recuperación restringida, gestión de sesiones y políticas de identidad, backup cifrado, restauración scratch y anclajes de auditoría locales. No implementa alta disponibilidad, despliegue productivo, IdP/SCIM, KMS/HSM, almacenamiento de objetos, correo, observabilidad central o WORM real.

El motor de persistencia es **PostgreSQL 18**. “Progress” se usa en la conversación como seguimiento del trabajo, no como Progress OpenEdge.

## Frontera segura del clúster

`packages/database/scripts/local-cluster.ps1` administra un clúster dentro de `packages/database/.local` y escucha solo en `127.0.0.1:55432`. Sus guardas:

- rechazan host no-loopback y puerto `5432`;
- no registran ni modifican el servicio PostgreSQL del sistema;
- validan rutas dentro de `packages/database/.local`;
- generan secretos aleatorios y no los imprimen;
- aplican ACL a la identidad operadora y SYSTEM; excluyen propietarios técnicos de sandbox y fallan si no pueden restringir el acceso;
- rehúsan estados parciales o nombres scratch no determinísticos.

ACL local es defensa en profundidad, no reemplazo de un gestor de secretos ni aislamiento frente a un administrador del host.

## Bootstrap reproducible

Desde la raíz:

```powershell
pnpm bootstrap:local
```

El script:

1. exige `pnpm-lock.yaml` e instala con `--frozen-lockfile`;
2. compila el workspace;
3. inicializa y arranca el clúster aislado;
4. migra el plano de control;
5. crea Demo y Ozama cuando faltan; si ya existen, valida su identidad/ruta y los preserva sin reprovisionar ni cambiar su estado;
6. aplica migraciones tenant solamente dentro de una base recién creada; toda actualización posterior usa el flujo explícito descrito abajo;
7. siembra exclusivamente Demo y reconcilia sus cinco perfiles de acceso aislados sin imprimir credenciales;
8. emite material de activación global solo cuando corresponde.

En el inventario fuente actual hay 26 archivos de migración de control y 38 archivos de migración tenant. Las cabezas son `026_invitation_enrollment_recovery_qualification.sql` y `036_transactional_invitation_grantor_lock.sql`. El runner registra por nombre de archivo, por lo que los prefijos históricos repetidos 005 y 017 no reducen el inventario real.

El chequeo persistente read-only incorporado al cierre de `2026-09-14T10:56:10.4065404Z`–`11:04:21.4060919Z` terminó `pass=true`, `mismatchCount=0`: control 26/26 con cabeza `026_invitation_enrollment_recovery_qualification.sql`; Demo y Ozama 38/38 con cabeza `036_transactional_invitation_grantor_lock.sql`; Demo 180 miembros/150 elegibles; y Ozama 47 tablas operativas/0 filas. No hubo migraciones pendientes o inesperadas, checksum divergente, drift de inventario/ownership/grants/roles/rutas ni backlog de workers. Este resultado forma parte del [`verify-local-final.json`](../artifacts/verify-local-final.json) actual, cuyo SHA-256 es `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6` y `closureEligible=true`. Ambos tenants conservan el catálogo técnico canónico `2025.1.0`, con 29 departamentos, 67 cargos y SHA-256 `sha256:c41426801200251a88b90c8d3dfc6f3f158332c3158e77adf1b4bd72e90c6fb8`; su aprobación institucional continúa `draft` y depende de validación externa. [`artifacts/continuity-restart-final.json`](../artifacts/continuity-restart-final.json) sigue siendo evidencia histórica separada.

### Advertencia de actualización 024–025

Al actualizar una base tenant anterior, las migraciones 024 y 025 reducen exposición histórica de forma deliberadamente irreversible: sustituyen títulos de sesión/agenda que estaban en claro por un marcador de redacción; neutralizan copias históricas del sobre combinado de perfil; y vencen/eliminan el contenido almacenado de reportes que pudiera incorporar ese perfil combinado. El sobre combinado del registro maestro del miembro queda en cuarentena hasta que un cliente con `member.contact.manage` lo reemplace por sobres `member-display` y `member-contact` separados, o descarte explícitamente el contacto.

Antes de aplicar estas migraciones a datos reales se requiere autorización del responsable, backup verificado y plan de reingreso/recifrado cliente. En Demo el seed sintético reconstruye los datos permitidos con el contrato separado; el último chequeo confirmó Ozama vacía, condición que debe volver a comprobarse en cada cierre. No se debe afirmar que una migración de servidor puede separar contenido cifrado cuya clave no posee.

Las migraciones 030 y 032 conservan su contenido/checksum histórico; los endurecimientos posteriores viven en las migraciones forward-only 031 y 033. Toda base persistente debe inspeccionarse con el preflight para distinguir inventario fuente de plan pendiente: no se debe deducir su estado aplicado a partir del ordinal máximo del repositorio.

### Actualización tenant con preflight y aprobación exacta

`db:migrate:tenants` nunca selecciona implícitamente “todos” ni aplica al invocarlo sin contexto. Exige un único UUID y un modo `preflight` o `apply`. Admite tenants `active` o `suspended` únicamente con `setup_state=ready`; también admite un tenant real `provisioning` solo cuando su último job está en `pending_activation`, su `setup_state` es `not_started` o `ready` —nunca `in_progress`— y todas sus tablas operativas existentes —47 en el esquema actual— están vacías. Rechaza cualquier otra combinación, incluidos estados `failed` o `decommission_pending`. El preflight no ejecuta DDL, DML ni ACL. Valida la ruta, el plan completo con checksum, `manifest.sha256`, el hash del payload, el tag GCM mediante descifrado con la llave histórica, bytes/SHA-256 del dump claro y la igualdad entre el invariante respaldado y el estado actual. El dump claro temporal y la copia de la llave en memoria se eliminan en `finally`.

La salida de contrato `schemaVersion: 2` incorpora `legacyInvitationReconciliation`: esquema fuente, cantidades exactas de invitaciones/bindings, SHA-256 del manifiesto estable y SHA-256 del snapshot de control. Estos campos forman parte del `approvalDigest`; no son observaciones informativas que puedan cambiar entre preflight y apply. Para una base anterior a la columna de procedencia, el inventario es exactamente vacío y no se infiere nada. Para una base con procedencia legacy, cada binding debe corresponder uno-a-uno con una invitación control `accepted`, el mismo tenant, `acceptance_id`, identidad, grantor, attempt monotónico, clase/epoch de autoridad y conjunto ordenado de roles. Cualquier ausencia, duplicado, tupla parcial o ambigüedad aborta antes de escribir.

Con API, web y workers detenidos, crear un backup, ejecutar el drill aislado y obtener la aprobación sin copiar ni calcular hashes a mano:

```powershell
$NomTenantId = '<tenant-uuid>'
$NomReentryPlan = 'change/approved-client-reentry-v1'
$NomBackupOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\backup-local.ps1 -Action backup -TenantId $NomTenantId
if ($LASTEXITCODE -ne 0) { throw 'Tenant backup failed.' }
$NomBackup = ($NomBackupOutput | Select-Object -Last 1) | ConvertFrom-Json

$NomDrillOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\backup-local.ps1 -Action drill -TenantId $NomTenantId -BackupDirectory $NomBackup.backupDirectory
if ($LASTEXITCODE -ne 0) { throw 'Tenant restore drill failed.' }
$NomDrill = ($NomDrillOutput | Select-Object -Last 1) | ConvertFrom-Json
if ($NomDrill.status -ne 'passed' -or -not $NomDrill.scratchRemoved -or $NomDrill.backupId -ne $NomBackup.backupId) {
  throw 'Restore drill evidence does not match the selected backup.'
}

try {
  $env:NOMBRAMIENTOS_TENANT_UPGRADE_ID = $NomTenantId
  $env:NOMBRAMIENTOS_TENANT_UPGRADE_BACKUP_ID = [string]$NomBackup.backupId
  $env:NOMBRAMIENTOS_TENANT_UPGRADE_REENTRY_PLAN_REFERENCE = $NomReentryPlan
  $env:NOMBRAMIENTOS_TENANT_UPGRADE_MODE = 'preflight'
  $NomPreflightOutput = & pnpm --filter @nombramientos/database db:migrate:tenants
  if ($LASTEXITCODE -ne 0) { throw 'Tenant migration preflight failed.' }
  $NomPreflight = ($NomPreflightOutput | Select-Object -Last 1) | ConvertFrom-Json
  if (-not $NomPreflight.approvalDigest) { throw 'Preflight returned no pending approved plan.' }

  $env:NOMBRAMIENTOS_TENANT_UPGRADE_APPROVAL = [string]$NomPreflight.approvalDigest
  $env:NOMBRAMIENTOS_TENANT_UPGRADE_MODE = 'apply'
  & pnpm --filter @nombramientos/database db:migrate:tenants
  if ($LASTEXITCODE -ne 0) { throw 'Tenant migration apply failed.' }
}
finally {
  Remove-Item Env:NOMBRAMIENTOS_TENANT_UPGRADE_APPROVAL -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_TENANT_UPGRADE_MODE -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_TENANT_UPGRADE_REENTRY_PLAN_REFERENCE -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_TENANT_UPGRADE_BACKUP_ID -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_TENANT_UPGRADE_ID -ErrorAction SilentlyContinue
}
```

La salida JSON de `preflight` contiene exclusivamente metadatos sanitizados: `tenantId`, `tenantLifecycle`, `maintenanceClass`, nombres/checksums pendientes, `backupId`, hash del payload, evidencia legacy y `approvalDigest`; nunca incluye bearer, raíz de recovery, secreto de capability ni hash de token. Si no hay migración ni reconciliación pendiente, los campos de backup/aprobación son `null`. Ese digest liga exactamente tenant, backup, payload, referencia del plan de reingreso, nombres/checksums y evidencia legacy; cualquier cambio obliga a repetir el preflight. `apply` repite todas las comprobaciones bajo locks, instala el manifiesto sólo como tabla `pg_temp` transaccional para la migración 036, rellena `source_acceptance_id` y su fence exacto en el mismo commit tenant, y sólo después finaliza el marcador initial-admin aplicable y un evento hash-chained de control con metadata exacta. Reconcilia ownership/grants y vuelve a validar el invariante pending-activation. Un plan DDL vacío todavía puede requerir apply cuando el commit tenant sobrevivió pero faltan el marcador o la evidencia control: ese reintento converge de forma idempotente y nunca reaplica ni inventa bindings.

La comprobación de sesiones concurrentes es una guarda adicional, no un cierre global. El runner toma primero el mismo advisory `tenant_identity_policy` que sesión/policy/invitación, después el lock de ruta compartido con provisión, las filas tenant/job y por último la autoridad exacta antes de las invitaciones; así evita invertir el orden con aceptación u offboarding. Aun así, un cliente tenant externo que no participe en esas fronteras podría conectarse después del chequeo. Por eso detener la aplicación y mantener una ventana de mantenimiento exclusiva es una precondición, no una recomendación. El tooling local aborta si detecta otra sesión y no la termina por fuerza; un despliegue real requiere un connection fence/orquestador de mantenimiento ensayado.

Ozama debe conservar **cero filas en las 47 tablas operativas actuales** hasta su activación real. No se admite allí fixture, importación, reporte ni historial legacy sintético; la política de mantenimiento falla de forma cerrada si cualquiera de las tablas operativas existentes deja de estar vacía. El chequeo persistente de solo lectura del cierre confirmó 38/38 migraciones y 0 filas; cada pase DB y drill posterior debe repetirlo.

No documentar ni copiar:

- `packages/database/.local/install.json`;
- `demo-access.json`;
- `platform-admin-bootstrap.json`;
- inventarios de claves de backup/auditoría;
- contraseñas, URLs de conexión, URI TOTP, tokens o claves.

## Arranque y parada

```powershell
pnpm start:local
```

`start:local` arranca PostgreSQL, worker, API y web como procesos separados, registra PIDs/horas y exige:

- `http://127.0.0.1:4000/healthz` con API y worker saludables;
- `http://127.0.0.1:3000/healthz` con web saludable, sin cookies ni redirección;
- `http://localhost:3000/es/auth/sign-in` con HTTP 200 como URL canónica de usuario para WebAuthn.

Si un proceso falla durante el arranque, detiene los procesos ya iniciados. Los logs locales están bajo `.local` y deben permanecer sin secretos.

Parada completa:

```powershell
pnpm stop:local
```

Parada de aplicación conservando la base para un ensayo de reinicio:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop-local.ps1 -KeepDatabase
```

La parada valida PID y hora de inicio para no terminar un proceso reutilizado; pide cierre limpio al worker antes de forzar.

## Worker y activación

El API ordinario inserta trabajos durables de aprovisionamiento, pero no recibe `DATABASE_ADMIN_URL` ni credenciales administrativas de tenants. El worker toma trabajos con bloqueo transaccional, heartbeat e idempotencia y ejecuta migración/aprovisionamiento.

Un tenant real termina en `pending_activation`. Un administrador global con autenticación fuerte emite una invitación inicial; el token se muestra una vez, la base conserva solo hash/estado/expiración y el destinatario completa el autenticador permitido por la política —passkey primaria o TOTP de transición/fallback— antes de recibir permisos. Ozama no recibe una identidad inventada por un script.

La recuperación del bootstrap global exige confirmación, un código cerrado no sensible y una referencia al expediente externo. La referencia se usa solo para calcular SHA-256: ni ella ni la narrativa del incidente se guardan en la base de control.

```powershell
$env:NOMBRAMIENTOS_PLATFORM_RECOVERY_CONFIRM = 'ROTATE_PLATFORM_ADMIN_BOOTSTRAP'
$env:NOMBRAMIENTOS_PLATFORM_RECOVERY_REASON_CODE = 'AUTHORIZED_RECOVERY'
$env:NOMBRAMIENTOS_PLATFORM_RECOVERY_INCIDENT_REF = '8f91754f-01d2-4c0b-ae44-b8dc7d12d77a'
pnpm db:bootstrap:platform-admin -- --recovery
Remove-Item Env:NOMBRAMIENTOS_PLATFORM_RECOVERY_CONFIRM
Remove-Item Env:NOMBRAMIENTOS_PLATFORM_RECOVERY_REASON_CODE
Remove-Item Env:NOMBRAMIENTOS_PLATFORM_RECOVERY_INCIDENT_REF
```

La referencia debe ser un UUID opaco e impredecible creado en el sistema de incidentes. Los códigos admitidos son `SECURITY_RESPONSE`, `ADMIN_ACCESS_LOSS` y `AUTHORIZED_RECOVERY`. El procedimiento revoca material pendiente; no suplanta ni desactiva silenciosamente una identidad activa. La justificación humana permanece en el expediente externo con sus propios controles de acceso y retención.

## Operación de autenticación enterprise

- URL de usuario: `http://localhost:3000/es/auth/sign-in` —`localhost`, no `127.0.0.1`, porque un RP ID WebAuthn no puede ser una dirección IP.
- API local: `http://localhost:4000`; PostgreSQL continúa únicamente en `127.0.0.1:55432`.
- Alta passkey: el usuario confirma en Windows Hello, Touch ID, Face ID, PIN o el autenticador ofrecido por el sistema. La aplicación nunca recibe una clave privada.
- Alta TOTP desde el mismo teléfono: usar “Abrir mi aplicación autenticadora”. Desde PC: usar el QR generado localmente o la clave manual. No usar un servicio externo de QR ni buscar semillas en archivos.
- Recuperación: un recovery code de un uso crea sólo una sesión `recovery_limited`; no entrega permisos tenant ni llave de contenido. Desde esa sesión se registra un autenticador de reemplazo y se revocan/rotan las sesiones dependientes.
- Pérdida de dispositivo: revocar la passkey y las sesiones desde el Centro de seguridad usando otra passkey; si no queda una, usar recovery code y la ruta limitada. No deshabilitar MFA desde SQL.
- Política: quien posee `tenant.settings.manage` puede editar en el Centro de seguridad el rollout, AAL general/privilegiado, cantidades de passkeys, postura privilegiada administrable, habilitación de contraseña/TOTP/recovery codes/passkeys sincronizadas y los límites de sesiones activas/inactividad/vida absoluta/TTL de step-up. La verificación local del usuario y la resistencia al phishing son pisos visibles pero deshabilitados para edición; la matriz de requisitos por acción es informativa y de solo lectura. Guardar sigue la vía API autorizada con CSRF, versión esperada y step-up; nunca se edita la base directamente.
- Invitaciones: quien invita debe poseer `role.manage` y una arista explícita en `system_role_assignment_matrix`. Esa matriz DB es read-only para runtime y hoy permite sólo a `CHURCH_ADMIN` asignar los seis roles de sistema admitidos; los roles locales personalizados conservan el límite separado de permisos delegables. Aceptación bloquea/revalida contexto y bindings del grantor. Desactivar grantor, membresía o tenant revoca invitaciones `pending`/`accepting`, y un guard final impide activar al invitado contra autoridad inactiva. El token de sesión resultante existe sólo en cookie `HttpOnly`; la sesión `enrollment_only` queda ligada a la invitación, sin permisos operativos y con máximo de diez minutos.
- Contraseña adaptativa: no solicitarla inicialmente. Si la política efectiva la exige, la API devuelve `INVITATION_PASSWORD_REQUIRED` antes de cualquier mutación y la UI revela el campo. Si la prohíbe, `password_provisioned=false` más un hash aleatorio de preimagen descartada garantiza que no exista una contraseña latente.

### Runbook: pérdida total durante el alta del administrador inicial

Usar esta vía sólo cuando la invitación inicial figure `accepted` y con autoridad finalizada, la identidad continúe activa y todavía no exista TOTP ni passkey. Si queda una passkey o recovery code utilizable, seguir la recuperación ordinaria del Centro de seguridad.

1. El administrador A abre la consola de plataforma, selecciona el candidato exacto, registra una referencia no sensible del expediente y confirma la solicitud mediante step-up WebAuthn. No copie bearer, cookies, hashes ni narrativas del incidente en tickets o logs.
2. El administrador B, distinto de A y del beneficiario, abre la cola “solicitados por otro administrador”, contrasta tenant, destinatario y referencia institucional por un canal humano independiente y aprueba mediante su propio step-up WebAuthn.
3. En local, `local_console` muestra el bearer una sola vez. Entréguelo al beneficiario mediante el canal verificado acordado; un replay de aprobación devuelve `reused=true` y nunca fabrica otro token. Si el valor se pierde, revoque el caso y cree otro; no lea la tabla ni busque tokens en archivos.
4. El beneficiario abre la pantalla de recuperación. El cliente precompromete primero el contexto `HttpOnly` y sólo entonces solicita el bearer. Al canjearlo recibe exclusivamente una sesión `enrollment_only` de hasta diez minutos y debe registrar de inmediato una passkey o TOTP. `admin_active` sólo aparece después de la transacción atómica que guarda el factor y emite la sesión AAL2.
5. Ante identidad, membresía, rol o sesión administrativa revocada, discrepancia de tuple, expiración, entrega dudosa o actividad sospechosa, use la acción de revocación gobernada y abra un caso nuevo. Nunca reactive el estado con SQL manual.

La operación local ofrece únicamente `local_console`. Producción permanece deliberadamente cerrada (`503 RECOVERY_DELIVERY_UNAVAILABLE`) hasta desplegar y aprobar un adaptador OOB con identidad de proceso separada, credencial rotada fuera del runtime HTTP, canal verificado, recibos, rate limits, observabilidad/SIEM, runbook de revocación y pruebas de entrega/replay. El rol DB de delivery es `NOLOGIN` y sólo posee las dos transiciones de confirmación/fallo; sin proceso y ciclo de secretos dedicados no es una integración operativa y no debe anunciarse como tal. Véase [Recuperación gobernada del administrador inicial](authentication.md#recuperación-gobernada-del-administrador-inicial).

La política base está en `monitor` para metas de assurance. Los controles criptográficos, consumo único, restricciones de recuperación, prohibiciones explícitas de método y límites de sesión permanecen activos. Cambiar a `enforce` puede bloquear identidades que aún no cumplen el piso; revisar findings y completar el enrolamiento antes. Una exigencia de attestation/dispositivo administrado falla cerrada si no existe FIDO Metadata Service/cadena de confianza.

Las migraciones control posteriores a 015 hacen inmutable el baseline global, ligan reemplazo passkey a ceremonia, serializan readiness de invitaciones, introducen enrolamiento passwordless, fijan techo MFA, hacen explícito `password_provisioned`, remedian credenciales legacy, bloquean el contexto activo durante emisión de sesión y gobiernan la recuperación cualificada del enrolamiento inicial. El baseline rechaza `INSERT`, `UPDATE`, `DELETE` y `TRUNCATE` runtime. No editar ese piso desde UI/API/SQL operativo. Una variación exige migración atómica que revalide policies, reconcilie sesiones e invalide WebAuthn/TOTP/grants. Las migraciones tenant posteriores añaden matriz de asignación y locks transaccionales de bindings para invitación/control de acceso. El cierre integral actual verificó su aplicación y checksums en modo read-only.

La remediación de contraseña legacy es deliberadamente fail-closed. Sólo sustituye un hash 019-era por el sentinel sin preimagen cuando la policy histórica puede probar `allowPassword=false`; entonces fija el marcador de scrub y revoca sesiones password/TOTP/recovery/bootstrap, challenges MFA y grants derivados. Si falta policy fechada o cambió después de aceptar, aborta la migración completa en vez de adivinar. No editar el sentinel, forzar el marcador ni resolver una ambigüedad manualmente sin expediente/migración dedicada.

Antes de confirmar un cambio, la transacción valida readiness sobre **todas** las identidades activas del tenant y bloquea el conjunto de membresías, credenciales y códigos de recuperación afectado. Si una identidad perdería su último camino permitido o no alcanzaría los mínimos aplicables, toda la actualización revierte. Si confirma, las ceremonias WebAuthn, los challenges TOTP activos y los grants de step-up aún pendientes de la versión anterior quedan invalidados, las sesiones que excedan el nuevo máximo se revocan y los plazos restantes se acortan a la nueva vida absoluta/inactividad sin extenderse. El audit de la actualización registra cuántas sesiones se revocaron/reconciliaron y cuántas ceremonias WebAuthn, challenges TOTP y grants se invalidaron.

Las altas simultáneas de passkey se serializan por identidad para que sólo una pueda completar el primer enrolamiento y para no exceder el máximo configurado. Las revocaciones concurrentes también se serializan y no pueden cruzar un mínimo `enforce` ni eliminar el último método de acceso. La creación de sesión bloquea la identidad, relee la política efectiva y aplica el cupo dentro de la misma transacción; no separar creación y recorte en tareas operativas independientes.

Password/TOTP, passkey y switch de tenant invocan la misma frontera `lock_active_authentication_context`: advisory lock de policy seguido de locks compartidos sobre identidad, membresía y tenant activos. La función `SECURITY DEFINER` expone sólo el booleano de actividad y no concede `UPDATE` a runtime. No cambiar el orden de locks ni sustituirlo por lecturas independientes; abriría una carrera entre offboarding/policy y emisión de sesión.

El tipo de dispositivo y el bit WebAuthn BE son inmutables después del registro: la base exige equivalencia entre `multiDevice` y BE, y el store rechaza un cambio de ambos entre ceremonias o Backup State verdadero con BE falso. UV se verifica en cada aserción. Al reemplazar una passkey, la anterior permanece activa hasta verificar la nueva; alta y revocación confirman en una sola transacción, por lo que fallo/cancelación conserva el acceso anterior.

Los fallos de contraseña y MFA comparten un presupuesto fijo por identidad: al octavo fallo se bloquea durante 15 minutos, aunque los fallos MFA provengan de challenges nuevos. Cada challenge MFA permite además un máximo de seis reservas atómicas; nunca se concede un séptimo intento por concurrencia. Los intentos durante el bloqueo no prolongan el vencimiento ni incrementan el contador; el primer fallo posterior al vencimiento inicia un contador nuevo. Un login primario correcto limpia el estado; una passkey criptográficamente válida no queda bloqueada por este contador y lo limpia sólo al completar correctamente.

Al cambiar de iglesia/tenant, la API evalúa primero la assurance y el método actuales contra la política destino. Una incompatibilidad responde `TARGET_TENANT_SECURITY_UPGRADE_REQUIRED` antes de rotar o revocar la sesión fuente. Si el preflight es compatible, la transacción destino relee los límites efectivos y recorta vida absoluta, inactividad y número de sesiones; después de rotar se reevalúa la policy para cubrir un cambio concurrente.

No cambiar `WEBAUTHN_RP_ID` después de enrolar credenciales: las passkeys quedan ligadas al RP. Producción exige decidir primero el dominio definitivo, DNS y TLS/HSTS; un cambio desde `localhost` requiere enrolamiento nuevo. Configuración, variables y modelo de assurance: [Autenticación enterprise](authentication.md).

El origen visible al navegador es canónicamente `localhost`. Una solicitud a `127.0.0.1`/`::1` en un puerto operativo conocido se redirige 307 en servidor hacia un destino fijo, preservando ruta/query, con `Cache-Control: no-store` y sin `Set-Cookie`; nunca construir el destino con `Host` o `X-Forwarded-Host`. Los endpoints que emiten cookies rechazan un `Origin` ausente/no permitido antes de crear sesión. Listeners y healthchecks siguen en `127.0.0.1`; el build inspecciona el bundle y falla si contiene `http://127.0.0.1:4000` en vez de la API canónica `http://localhost:4000`. El AppShell debe dejar `enrollment_only` y `recovery_limited` renderizados en el Centro de seguridad, fuera del cálculo de redirect, para no reintroducir el bucle de navegación.

### Reverse proxy confiable y dirección cliente

En local, `API_TRUSTED_PROXY_CIDRS` se deja sin valor: Fastify usa `trustProxy=false` e ignora `X-Forwarded-For`, incluso si la conexión directa proviene de loopback. Cuando exista un reverse proxy, configurar exclusivamente las IP/CIDR exactas del **peer inmediato** separadas por coma:

```text
API_TRUSTED_PROXY_CIDRS=<ip-o-cidr-del-proxy>[,<segunda-ip-o-cidr>]
```

No usar `0.0.0.0/0`, `::/0`, alias amplios ni la red completa de clientes. El parser valida IPv4/IPv6/CIDR, elimina duplicados y rechaza entradas vacías o wildcard; la cadena se resuelve desde el proxy más cercano hacia el cliente. En `NODE_ENV=production` una allowlist vacía impide arrancar, de modo que rate limiting y señales de sesión nunca confían silenciosamente en headers reenviados. La allowlist debe provenir de la topología desplegada y volver a probarse detrás del balanceador/TLS real; los tests loopback de fuente no certifican esa infraestructura.

## Verificación integral

Con los servicios saludables:

```powershell
pnpm verify:local
```

El target exige integración live y ejecuta supply chain, auditoría de dependencias, tipos, lint, build limpio, suites PostgreSQL/API/web, Playwright, render PDF, escaneo del delivery, estado persistente, salud terminal e integridad fuente. El artefacto actual de `2026-09-14T10:56:10.4065404Z` a `11:04:21.4060919Z` aprobó 25 etapas y aceptó exclusivamente la sonda Firefox opcional; registró 1.196/1.196 pruebas no Playwright —39 de verificación, 41 de dominio, 31 E2EE, 441 de base, 417 de API y 227 web— y Playwright 106 aprobadas + 54 exclusiones exactas de 160, con cero fallos. Chromium y WebKit fueron obligatorios y pasaron; Firefox quedó excluido por el probe nativo Windows `exit 2`. La matriz probó la redirección absoluta del origen IP al `localhost` fijo en sus cuatro perfiles activos. La huella de los 654 archivos de fuente fue idéntica al inicio, final y publicación: `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f`. El JSON canónico mide 41.090 bytes y tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6`. El pase local no sustituye homologación de infraestructura, seguridad o accesibilidad productiva independiente. Véase [verification.md](verification.md).

## Backup cifrado por tenant

Configurar la llave local dedicada:

```powershell
pnpm --filter @nombramientos/database db:backup:configure
```

Crear backup explícito de Demo:

```powershell
pnpm --filter @nombramientos/database db:backup:demo
```

Para otro tenant, el wrapper exige UUID; no existe opción implícita “todos”:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\backup-local.ps1 -Action backup -TenantId <tenant-uuid>
```

El backup:

- exporta un snapshot `REPEATABLE READ READ ONLY`;
- usa `pg_dump` 18 sin contraseña en argumentos/salida;
- cifra el dump mediante AES-256-GCM con llave independiente;
- autentica con AAD el núcleo canónico del manifiesto;
- registra hashes, esquema, catálogo, inventario, secuencias y cabezas de auditoría/outbox;
- elimina el dump claro temporal en `finally`.

Los artefactos quedan bajo `.local/backups/<tenant>/<timestamp>-<id>/`. Perder `backup-keys.json` hace irrecuperables los backups locales. Rotar solo mediante:

```powershell
pnpm --filter @nombramientos/database db:backup:key:rotate
```

La versión anterior se conserva como `retired` para restauración histórica. Véase [`packages/database/BACKUP.md`](../packages/database/BACKUP.md).

## Ensayo de restauración aislada

```powershell
pnpm --filter @nombramientos/database db:restore:drill:demo
```

El drill valida manifiesto, checksum, tag, tenant, base, credencial, migraciones, filas, secuencias y cabezas; crea solo un nombre `nom_restore_<tenant8>_<backup8>`, nunca sobrescribe una base existente, compara antes/después todos los demás tenants elegibles para mantenimiento y limpia scratch/temporales incluso al fallar. La salida enumera `comparedTenantIds` y `comparedTenantCount`, y exige cobertura exacta y sin duplicados. Un despliegue legítimo sin otro tenant elegible no necesita fabricar uno para probar su restauración; el aislamiento cruzado se valida además en la suite de integración dedicada.

Un ensayo local histórico documentado sobre Demo —anterior al inventario/política actuales y no sustitutivo del drill final— registró:

- backup/restauración e invariantes: `passed`;
- Ozama sin cambios y scratch eliminado: `true`;
- edad conservadora del punto de recuperación: 0,922 s;
- restauración/verificación/limpieza: 0,675 s.

Son cifras de un dataset sintético local, no garantía de RPO/RTO productivo. El rerun final del 13-09-2026 creó backups nuevos de Demo y Ozama y aprobó ambos drills simétricos, con RPO/RTO local satisfecho, scratch eliminado y el único tenant vecino sin cambios; véase [verification.md](verification.md).

## Checkpoints y anclajes locales

```powershell
pnpm --filter @nombramientos/database build
powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\audit-anchor-local.ps1 -Action checkpoint -TenantId d0000000-0000-4000-8000-000000000001
powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\audit-anchor-local.ps1 -Action verify -TenantId d0000000-0000-4000-8000-000000000001
powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\audit-anchor-local.ps1 -Action drill -TenantId d0000000-0000-4000-8000-000000000001
```

`-Action configure` se reserva exclusivamente para la configuración inicial cuando no exista inventario. `checkpoint` también puede crear un inventario si realmente falta, por lo que una ceremonia rutinaria debe comprobar antes que `audit-signing-keys.json`, ledgers y receipts existen y son accesibles. `Access Denied` no significa “ausente”: nunca borrar, regenerar ni ejecutar `configure` para sortear permisos o errores. La herramienta recomputa la cadena tenant, crea checkpoints y anclajes Ed25519 con llaves separadas, conserva generaciones/recibos y detecta alteración, borrado, truncamiento, reordenamiento, firma inválida y rollback. El drill modifica solo una copia temporal.

> **CIERRE_ANCLAJE_FINAL: APROBADO EN LABORATORIO.** La revalidación actual terminó `checkpoint=completed` sobre 1274 eventos Demo y dejó 5 checkpoints y 5 anclas —secuencia 5—. `verify` pasó; el drill detectó 5/5 manipulaciones previstas, registró `databaseWrites=0`, ejecutó la transacción read-only y eliminó todos sus temporales.

El ledger sigue en el mismo host y sus llaves son exportables. Producción requiere WORM con retención bloqueada, otra cuenta/dominio administrativo, KMS/HSM, monitoreo, rotación y restauración contra una cabeza externa. Véase [`packages/database/AUDIT-ANCHORS.md`](../packages/database/AUDIT-ANCHORS.md).

## Prueba de persistencia tras reinicio

El cierre local debe conservar antes de parar únicamente invariantes no sensibles: conteos autorizados, versiones y hashes. Luego:

1. detener aplicación con `-KeepDatabase`;
2. iniciar de nuevo con `pnpm start:local`;
3. comprobar health, sesión nueva, reportes/ciclos esperados y mismos invariantes;
4. confirmar que todas las tablas operativas actuales de Ozama —47 en este corte— siguen en cero.

> **REINICIO HISTÓRICO Y DB ACTUAL.** El artefacto de continuidad conserva la evidencia histórica del reinicio con 921 eventos y ancla 2; sus cinco muestras terminales y el estado control 14/14 pertenecen a ese corte y no se reescriben. La comprobación read-only del verify actual confirmó `pass=true`, `mismatchCount=0`, control 26/26 cabeza 026, Demo 38/38 y 180/150, y Ozama 38/38 con 47 tablas/0 filas. La salud de API, web y worker también quedó aprobada al publicar el cierre.

## Ambientes

| Ambiente | Datos | Secretos | Servicios externos |
|---|---|---|---|
| Desarrollo | sintéticos; Ozama debe permanecer vacía y su estado final se revalida | archivos locales con ACL | ninguno |
| Pruebas | fixtures/tenants efímeros | efímeros | ninguno |
| Producción | no habilitada | KMS/HSM por aprobar | pendientes |

Nunca reutilizar credenciales, claves, objetos o bases entre ambientes.

## Observabilidad y continuidad pendientes

No hay stack de observabilidad conectado. Producción requiere, como mínimo:

- métricas/SLO de disponibilidad, latencia, pool, cola, migración y autorización;
- alertas de 401/403/409/429/5xx, outbox atrasado, discrepancia, backup/restore/anclaje vencido y certificados;
- logs con IDs opacos y sin nombres, notas, candidatos, boletas ni secretos;
- runbooks ensayados para pérdida de conexión, carrera de cierre, discrepancia de custodios, dispositivo perdido, cruce tenant, cuenta comprometida, backup/anclaje corrupto y vulnerabilidad crítica;
- TLS, rotación, backups fuera del host, RPO/RTO con volumen y WORM real.

## Checklist externo antes de producción

- validación denominacional/jurisdiccional de Ozama;
- privacidad, residencia, retención, contratos y proveedores aprobados;
- dominio RP/DNS/TLS/HSTS, IdP/SCIM, FIDO MDS/attestation cuando aplique, KMS/HSM, correo, objetos y observabilidad ensayados;
- restauración a escala y anclaje WORM independiente;
- pentest y revisión criptográfica;
- accesibilidad manual y pruebas físicas iOS/Android/Windows/macOS;
- revisión de traducciones, marca/manual y licencias;
- procedimiento de despliegue, rollback y respuesta a incidentes.

Todos permanecen abiertos salvo evidencia externa aprobada y fechada.
