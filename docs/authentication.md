# Autenticación enterprise: operación y despliegue

Estado técnico local: implementado. Este documento describe el comportamiento verificable de la aplicación y separa expresamente lo que depende del despliegue productivo. No constituye una certificación NIST, FIDO, OWASP ni de un tercero.

> **EVIDENCIA LOCAL ACTUAL: APROBADA.** El cierre [`verify-local-final.json`](../artifacts/verify-local-final.json) de `2026-09-14T10:56:10.4065404Z` a `11:04:21.4060919Z` registra `result=passed`, `overallPass=true`, `closureEligible=true`, 26 etapas —25 aprobadas y Firefox opcional aceptado—, 1.196/1.196 pruebas no-Playwright y una matriz Playwright de 160 resultados —106 aprobados, 54 omisiones exactas allowlisted y 0 fallos— con Chromium/WebKit obligatorios verdes. El archivo mide 41.090 bytes, tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6` y liga inicio, fin y publicación a 654 archivos con huella `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f`. La ceremonia real-stack vigente aprobó 4/4 y preservó las huellas protegidas; su [artefacto](../artifacts/real-browser-stack-local.json), de 3.953 bytes, tiene SHA-256 `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`. Esto acredita el laboratorio descrito, no un despliegue o certificación productivos.

## Arquitectura de métodos

| Método | Uso | Garantía local | Restricciones |
|---|---|---|---|
| Passkey WebAuthn | Primario, login y step-up | AAL2 técnico con presencia y verificación de usuario; resistente a phishing | AAL3 no se declara sin autenticador hardware, attestation confiable y controles operativos externos |
| Contraseña + TOTP | Fallback y transición | AAL2 no resistente a phishing | Puede deshabilitarse por tenant; nunca sustituye un step-up WebAuthn exigido |
| Código de recuperación | Recuperación offline | Sesión `recovery_limited` AAL1 | Sin permisos del tenant, sin clave de contenido y sin operaciones privilegiadas |
| Contraseña sola | Bootstrap o política que la permita | AAL1 | Una política en enforcement puede obligar a completar un autenticador fuerte antes del acceso |

La autenticación de la cuenta es independiente del desbloqueo E2EE. Tras entrar con passkey, las áreas que contienen datos cifrados pueden solicitar la contraseña de custodia para desenvolver la clave exclusivamente en el navegador. Esto evita enviar contenido o claves en claro a la API.

## Activación por invitación

La invitación no obliga a crear una contraseña cuando la política del tenant privilegia passkeys. El primer envío contiene el token de un solo uso y el nombre visible, pero omite la contraseña. La base bloquea la política efectiva y decide atómicamente:

- si `allowPassword=false`, crea la identidad con `password_provisioned=false` y un hash Argon2id aleatorio cuya preimagen se descarta; ese valor nunca puede convertirse en una credencial utilizable aunque la política cambie después;
- si `allowPassword=true`, responde `INVITATION_PASSWORD_REQUIRED` antes de mutar identidad, membresía, invitación o sesión; la interfaz revela y enfoca entonces los campos de contraseña y permite reintentar el mismo token;
- solo después de satisfacer la política se activan roles, se consume la invitación y se emite una sesión `enrollment_only` ligada a esa invitación por un máximo de diez minutos.

Los intentos de login para una identidad sin contraseña provisionada o para un tenant que no permite contraseña realizan trabajo Argon2id equivalente y devuelven el mismo error genérico. No existe un oráculo remoto que permita comprobar una contraseña latente.

La remediación forward-only de identidades aceptadas durante la ventana histórica de la migración 019 destruye una contraseña capturada cuando puede probar, con la policy fechada, que password estaba deshabilitado al aceptar. Sustituye el hash por un sentinel Argon2id sin preimagen, fija `password_provisioned=false`, marca el scrub y revoca sesiones password/TOTP/recovery/bootstrap, challenges MFA y grants derivados. Si el historial de policy es ambiguo, la migración completa falla y revierte en lugar de adivinar o inutilizar una contraseña legítima.

La invitación tampoco puede usarse para ampliar privilegios. Al crearla, la base exige contexto tenant ligado, identidad otorgante activa y `role.manage`. Los roles de sistema se gobiernan mediante una matriz relacional de asignación, de sólo lectura para runtime y propiedad de migraciones; no se deducen de los permisos operativos del rol. La configuración actual permite a `CHURCH_ADMIN` asignar los seis roles de sistema admitidos y no concede aristas a los demás roles. Los roles locales personalizados conservan sus límites independientes de permisos delegables.

La aceptación vuelve a comprobar la matriz dentro de la transacción antes de activar roles. Primero bloquea el contexto activo del grantor y luego todas sus bindings vigentes; una revocación concurrente queda serializada. Si se desactiva la identidad otorgante, su membresía o el tenant, triggers de control revocan toda invitación `pending`/`accepting` con códigos normalizados. Un guard final al insertar/activar la membresía invitada impide confirmar contra un grantor ya inactivo. Las funciones `SECURITY DEFINER` no confían en IDs tenant/grantor enviados por el cliente y no amplían privilegios de tablas al runtime.

El token de sesión de enrolamiento se entrega exclusivamente como cookie `HttpOnly`, nunca en el cuerpo JSON. La sesión queda marcada `enrollment_only`, ligada por base a la invitación consumida, sin permisos operativos, y su vencimiento se limita en servidor/base a un máximo de diez minutos. El cuerpo sólo expone la vista pública de sesión y el CSRF necesario para las siguientes solicitudes; ni el token de invitación ni el token de sesión se vuelven a publicar.

## Recuperación gobernada del administrador inicial

Este flujo existe únicamente para un administrador inicial cuya invitación ya fue aceptada y finalizada, pero que perdió por completo la cookie o el perfil del navegador antes de registrar su primer factor fuerte. No sustituye la recuperación ordinaria por passkey/recovery code y nunca permite deshabilitar MFA, buscar un código en un archivo ni convertir una contraseña —provisionada o deshabilitada— en factor fuerte.

La recuperación aplica doble control independiente:

1. Un primer `platform_admin` activo selecciona el candidato sanitizado y firma con WebAuthn una solicitud ligada al UUID de recuperación, al tuple exacto `tenant/invitation/acceptance/identity/attempt/epoch/version`, al método, ruta y cuerpo canónicos. El grant se consume dentro de la misma transacción SQL que crea el caso.
2. Un segundo `platform_admin`, distinto tanto del solicitante como del beneficiario, descubre el caso en la cola gobernada y firma con otra credencial WebAuthn una aprobación ligada a la misma fuente y versión. La aprobación revalida las dos identidades, sesiones, membresías, roles y credenciales; no puede autoelevar al beneficiario.
3. La aprobación local pone en cuarentena todas las sesiones activas, challenges MFA, grants y ceremonias WebAuthn del beneficiario, sin tocar las sesiones de los dos administradores. El bearer de 256 bits se entrega una sola vez y PostgreSQL conserva únicamente SHA-256.
4. Antes de enviar el bearer, el navegador debe completar `POST /v1/auth/initial-admin-recovery/prepare-context`. Esa respuesta `204` vacía instala una raíz aleatoria host-only, `HttpOnly`, `SameSite=Strict` y limitada a la ruta de recuperación. Se aceptan hasta doce raíces auténticas para pestañas, reintentos y dispositivos coordinados; preparar contexto y consumir el bearer nunca ocurren en la misma respuesta.
5. `POST /v1/auth/initial-admin-recovery/redeem` exige el bearer en el primer consumo y una raíz precomprometida. Sólo emite una cookie de sesión `enrollment_only`, ligada al recovery y a la invitación, con máximo de diez minutos. Un retry de respuesta perdida puede rotarla desde el mismo contexto; hay cuatro redenciones totales, siempre con una sola sesión recovery activa. La raíz no se borra al éxito para permitir recuperación de respuesta perdida, pero la base deja de admitirla al finalizar un factor fuerte o alcanzar un estado terminal.
6. El beneficiario registra una passkey o TOTP desde el Centro de seguridad. Autorización recovery, locks, persistencia del factor, emisión de la nueva sesión AAL2 y transición `admin_active` comparten una sola transacción. Si solicitante o aprobador pierde autoridad antes de finalizar, el recovery se revoca como transición de sistema y no se activa el factor ni queda una sesión fuerte parcial.

Estados visibles: `pending` (espera segundo administrador), `finalization_pending` (aprobado/entregado), `enrollment_pending` (sesión restringida emitida), `admin_active` (factor fuerte y sesión AAL2 confirmados) y terminales `revoked`, `expired` o `failed`. La cola y los resúmenes omiten bearer, hashes de cookie, grants, operations y referencia de caso; el runtime no tiene `SELECT` sobre la tabla ni la vista base.

Rutas del contrato:

- `GET /v1/platform/initial-admin-recoveries/candidates`
- `GET /v1/platform/initial-admin-recoveries`
- `POST /v1/platform/initial-admin-recoveries`
- `POST /v1/platform/initial-admin-recoveries/{recoveryId}/approve`
- `POST /v1/platform/initial-admin-recoveries/{recoveryId}/revoke`
- `POST /v1/auth/initial-admin-recovery/prepare-context`
- `POST /v1/auth/initial-admin-recovery/redeem`

Las mutaciones administrativas usan la cabecera estándar `x-step-up-grant`; cualquier cambio de path, query o cuerpo invalida el grant. `local_console` está habilitado exclusivamente en desarrollo/test y devuelve el bearer sólo cuando `reused=false`. En producción, y para `verified_email`, `verified_sms` o `service_desk`, la API responde `503 RECOVERY_DELIVERY_UNAVAILABLE` antes de crear/persistir un bearer mientras no exista un adaptador fuera de banda aprobado. Las funciones de confirmación/fallo de entrega están aisladas en un rol PostgreSQL `NOLOGIN` que el runtime HTTP no puede usar; ese rol no constituye por sí solo un canal operativo.

## Flujo passkey

### Alta inicial

1. Una invitación o login válido crea una sesión restringida de enrolamiento cuando la identidad aún no tiene un autenticador fuerte requerido.
2. `POST /v1/auth/passkeys/registration/options` crea opciones con credencial descubrible y user verification obligatoria.
3. El navegador invoca WebAuthn mediante `@simplewebauthn/browser`; Windows Hello, Touch ID, Face ID, PIN o el autenticador disponible confirma localmente.
4. `POST /v1/auth/passkeys/registration/verify` valida challenge, origen, RP ID, tipo, presencia, verificación, algoritmo y firma.
5. La base consume la ceremonia atómicamente, guarda solo material público/metadatos, revoca la sesión restringida y emite una nueva sesión AAL2.

### Alta de una passkey adicional

Una identidad con passkey activa no puede agregar otra usando únicamente una sesión TOTP reciente. La solicitud de opciones responde con `WEBAUTHN_STEP_UP_REQUIRED`; el cliente realiza una verificación WebAuthn y obtiene un grant breve, opaco y de un solo uso ligado exactamente a `POST /v1/auth/passkeys/registration/options` y al cuerpo `{}`. El replay o cualquier variación falla cerrado.

### Login

`POST /v1/auth/passkeys/authentication/options` es deliberadamente usernameless. No consulta ni revela si un correo existe; la credencial descubrible identifica la cuenta. `POST /v1/auth/passkeys/authentication/verify` valida la aserción, actualiza de forma atómica contador/backup state, aplica el límite de sesiones y rota cookies.

El tipo de dispositivo y el bit Backup Eligibility (BE) son propiedades inmutables de la credencial registrada. La base exige equivalencia entre `device_type='multiDevice'` y `backup_eligible`; en cada aserción el store rechaza un cambio de tipo o BE y rechaza `backup_state=true` cuando BE es falso. Backup State puede evolucionar sólo dentro de esa capacidad declarada y User Verification se vuelve a exigir/evaluar en cada ceremonia: no se infiere de una ceremonia anterior.

Cuando el usuario selecciona una passkey para reemplazar, el ID queda ligado a la ceremonia de registro. La passkey anterior permanece activa mientras se crea y verifica la nueva. Sólo después de una verificación completa la base inserta la nueva y revoca la anterior dentro de la misma transacción; cancelación, caducidad, fallo de firma o error de persistencia conservan la anterior sin una ventana de bloqueo de cuenta.

### Gestión

- `GET /v1/auth/passkeys`: inventario público sin clave pública ni ID externo de credencial.
- `PATCH /v1/auth/passkeys/{id}`: nombre cosmético con control optimista de versión.
- `DELETE /v1/auth/passkeys/{id}`: step-up WebAuthn ligado a la operación; revoca sesiones y grants dependientes.
- `GET /v1/auth/sessions`: sesiones activas propias, dispositivo, método, AAL y expiraciones.
- `DELETE /v1/auth/sessions/{id}` y `POST /v1/auth/sessions/revoke-others`: step-up de un uso y revocación inmediata.

## TOTP en teléfono y PC

El alta TOTP tiene tres presentaciones de una misma semilla de ceremonia:

- Móvil, misma pantalla: botón explícito para abrir una URI `otpauth://totp/...` en la aplicación autenticadora. Antes de usarla, el cliente valida esquema, autoridad, parámetros obligatorios, secret Base32 y algoritmo.
- PC: QR generado localmente con `qrcode`; no existe servicio remoto de QR.
- Alternativa accesible: clave manual visible/copiable durante la ceremonia.

Solo `enrollmentId` y expiración —nunca semilla, URI ni recovery codes— pueden quedar temporalmente en `sessionStorage`. Tras una recarga, esa referencia permite confirmar con el código del autenticador ya configurado o cancelar/reiniciar; el servidor no vuelve a entregar la semilla/URI. Confirmar, cancelar o expirar elimina el estado pendiente. Los diez recovery codes se muestran una sola vez y se almacenan únicamente con hash Argon2id.

Cada challenge MFA permite reservar como máximo **seis** intentos, de forma atómica. La migración 020 normaliza cualquier fila heredada por encima del techo, fija la restricción `0..6` y evita que solicitudes concurrentes obtengan un séptimo intento. Este límite por challenge complementa —no reemplaza— el presupuesto fijo por identidad compartido entre contraseña y MFA.

En teléfono no se exige escanear la propia pantalla: la ruta recomendada abre directamente la aplicación autenticadora y regresa a Nombramientos para introducir el código. En PC, el QR permite usar un teléfono separado; la clave manual es la alternativa universal y accesible. TOTP es un fallback opcional, no un requisito adicional cuando una passkey ya satisface la política efectiva.

La experiencia de recuperación/enrolamiento se mantiene dentro del Centro de seguridad. El AppShell excluye explícitamente sesiones `recovery_limited` del cálculo de redirección a la página de entrada y renderiza el gate de recuperación; aplica el mismo principio a `enrollment_only`. Así una persona en teléfono o PC no entra en un bucle entre la ruta solicitada y el destino de seguridad. Tras aceptar una invitación, el cliente actualiza caché/sesión y navega al Centro de seguridad; si la API devuelve `INVITATION_PASSWORD_REQUIRED`, revela y enfoca la contraseña sólo entonces, sin pedirla preventivamente a quienes usarán passkey.

## Cookies, CSRF y ceremonias

- Sesión: cookie HttpOnly, SameSite y Secure cuando hay TLS; token aleatorio almacenado como hash. Las sesiones de invitación/enrolamiento tampoco entregan ese token en JSON.
- CSRF: cookie legible por el cliente más cabecera `x-csrf-token`, comparadas y verificadas contra el hash de sesión.
- WebAuthn: cada ceremonia usa una cookie HttpOnly independiente `nom_webauthn_<ceremony-id>`, SameSite Strict, alcance `/v1/auth/passkeys` y duración igual a la ceremonia. Su valor es un envelope AES-256-GCM ligado al ID, tipo y nombre de cookie; registro, login y step-up pueden coexistir en varias pestañas sin compartir ni sobrescribir el bearer opaco.
- Ceremonias: challenge/token con entropía criptográfica, persistidos como SHA-256, origen/RP/tipo ligados, caducidad corta, intentos acotados y consumo único transaccional.
- Step-up: cabecera `x-step-up-grant`; el servidor conserva solo su hash y lo liga a identidad, tenant, sesión, credencial, propósito y SHA-256 canónico de método/ruta/cuerpo.

Toda emisión de sesión —password/TOTP, passkey y cambio de tenant— usa la misma frontera transaccional: toma primero el advisory lock de policy y después locks compartidos sobre la identidad, membresía y tenant activos. La función `SECURITY DEFINER` devuelve sólo un booleano y no concede `UPDATE` sobre esas tablas al runtime. Así una baja o cambio de policy concurrente se ordena antes o después de la sesión; nunca se acuña desde un snapshot de autoridad obsoleto.

## Política global y por tenant

`GET /v1/auth/policy` devuelve la política efectiva y la postura de la sesión. `PATCH /v1/auth/policy` requiere `tenant.settings.manage`, CSRF, control de versión y step-up WebAuthn.

La política global es un piso que un tenant no puede debilitar. Controla:

- `monitor` o `enforce` para metas de AAL, cantidad de passkeys y postura privilegiada;
- AAL mínimo general y privilegiado;
- resistencia a phishing, dispositivo no sincronizable y attestation para privilegios;
- habilitación de contraseña, fallback TOTP, recovery codes y passkeys sincronizadas;
- cantidades mínima/máxima de passkeys y máximo de sesiones activas;
- timeout por inactividad, vida absoluta y duración del grant de step-up;
- requisitos por acción.

`monitor` muestra findings sin bloquear la migración. `enforce` aplica las metas de garantía. En ambos modos permanecen activos los controles criptográficos, consumo único, recuperación restringida, prohibiciones explícitas de métodos y límites de sesión.

La UI no afirma que una credencial sea attested si no existe una cadena de confianza comprobada. Cuando una política exige attestation/AAL3 sin FIDO Metadata Service y autenticadores administrados, el sistema falla cerrado.

## Configuración local

La aplicación escucha solo en loopback. Para usar WebAuthn local:

```text
Web: http://localhost:3000
API: http://localhost:4000
PostgreSQL: 127.0.0.1:55432
WEBAUTHN_RP_ID=localhost
WEBAUTHN_EXPECTED_ORIGINS=http://localhost:3000
API_CORS_ORIGINS=http://localhost:3000
```

`localhost` es la excepción de desarrollo permitida por WebAuthn sobre HTTP. Los procesos siguen enlazados a `127.0.0.1`, pero el navegador siempre usa `localhost`. Un acceso por `127.0.0.1` o `::1` se redirige en el servidor antes de renderizar formularios, aceptar tokens o emitir cookies. La respuesta contiene un `Location` absoluto construido desde un mapa fijo, preserva ruta/query y permite que el navegador conserve el fragmento original; nunca deriva el destino de `Host` ni `X-Forwarded-Host`. La defensa cliente mantiene además bloqueada la captura de credenciales si una página antigua llega a hidratarse en un origen no canónico.

La redirección usa 307, `Cache-Control: no-store` y elimina cualquier `Set-Cookie`; sólo existe para los puertos operativos locales conocidos. `/healthz` conserva 200 sobre IP y no recibe `Location`. Los cuatro perfiles Playwright verificaron la respuesta frente a cabeceras `X-Forwarded-Host`/`X-Forwarded-Proto` hostiles, la navegación efectiva con path/query/fragmento y que la opción passkey siga disponible al llegar a `localhost`. Los listeners y healthchecks continúan en `127.0.0.1`, mientras las URLs que ve el navegador y CORS usan `localhost`. Un gate de build inspecciona los chunks de navegador: exige la referencia canónica `http://localhost:4000` y falla si se hornea `http://127.0.0.1:4000` o su equivalente IPv6.

La cookie de sesión permanece host-only. En producción, el patrón recomendado es un único origen público HTTPS con `/v1` encaminado internamente al API loopback; así navegador, cookies, CORS y RP ID comparten una frontera inequívoca. Si una topología separa web y API, ambos deben ser HTTPS y schemefully same-site, y el smoke test de navegador/cookies pasa a ser obligatorio. Todo endpoint de navegador que emite una sesión valida el `Origin` canónico antes de llamar al servicio y falla sin `Set-Cookie` si falta o no coincide.

Variables API relevantes:

- `WEBAUTHN_RP_NAME`
- `WEBAUTHN_RP_ID`
- `WEBAUTHN_EXPECTED_ORIGINS` (lista exacta, separada por comas)
- `WEBAUTHN_CHALLENGE_TTL_SECONDS`
- `WEBAUTHN_STEP_UP_TTL_SECONDS`
- `API_CORS_ORIGINS`
- `API_SESSION_TTL_SECONDS`
- `AUTH_ENCRYPTION_KEY_B64` (32 bytes Base64URL; nunca se documenta su valor)

La API rechaza en producción un RP ID de loopback, un RP ID con esquema/puerto/path, un origen no HTTPS, orígenes que no sean iguales o subdominio válido del RP ID y cualquier origen fuera de CORS.

## Estado persistente verificable

La fuente congelada contiene 26 migraciones de control, cabeza `026_invitation_enrollment_recovery_qualification.sql`, y 38 migraciones tenant, cabeza `036_transactional_invitation_grantor_lock.sql`. El cierre integral actual terminó `pass=true`, `mismatchCount=0`: control 26/26; Demo y Ozama 38/38; Demo 180 miembros/150 elegibles; Ozama `pending_activation`, 47 tablas operativas/0 filas; todos los conteos de drift, backlog y discrepancia quedaron en cero. La ceremonia real-stack actual de `2026-09-14T10:55:31.681Z` a `10:55:43.495Z` volvió a comprobar cleanup y huellas protegidas sin cambios. Estos resultados prueban reconciliación local de fuente, esquema y datos protegidos para el corte publicado; deben repetirse tras cualquier cambio y no sustituyen controles productivos.

## Señales de contexto y privacidad

El user-agent normalizado y el prefijo de red se transforman a SHA-256. Un cambio incrementa contadores y fecha de señal, pero no actúa como identificador de persona ni bloquea por sí solo una sesión móvil legítima. Las operaciones sensibles siguen requiriendo la autorización criptográfica correspondiente. No se persiste la IP cruda en la sesión de autenticación.

## Qué falta para un despliegue Fortune 500 verificable

El software local implementa el comportamiento anterior, pero la calificación organizacional requiere controles externos que no pueden inventarse dentro del repositorio:

1. dominio RP definitivo, DNS, TLS/HSTS y protección perimetral productiva;
2. IdP corporativo OIDC/SAML, aprovisionamiento SCIM y gobierno del ciclo de vida de identidades;
3. KMS/HSM, rotación de secretos, separación de funciones y recuperación institucional;
4. FIDO Metadata Service, política de AAGUID/attestation y autenticadores administrados si se pretende AAL3;
5. SIEM, ancla WORM externa, alertas independientes y proceso SOC;
6. pruebas físicas en las versiones soportadas de iOS, Android, Windows y macOS;
7. pentest, revisión criptográfica/privacidad independiente, threat model aprobado y ejercicios de incidente/recuperación;
8. evidencias de cumplimiento y aceptación formal por los propietarios institucionales.

Hasta cerrar esos puntos, la expresión precisa es “implementación técnica local endurecida y verificable”, no “certificación Fortune 500”.
