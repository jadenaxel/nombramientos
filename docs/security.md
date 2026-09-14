# Seguridad

## Postura actual

Objetivo de ingeniería: controles aplicables de OWASP ASVS **5.0.0 nivel 2**, reforzados para aislamiento, privilegios, votación y claves. **No existe certificación ASVS ni auditoría criptográfica independiente en esta entrega.** La trazabilidad versionada está en [asvs-matrix.md](asvs-matrix.md).

> **EVIDENCIA AUTOMATIZADA LOCAL ACTUAL: VERDE.** [`verify-local-final.json`](../artifacts/verify-local-final.json) registra el run UTC `2026-09-14T10:56:10.4065404Z`–`11:04:21.4060919Z` con `result=passed`, `overallPass=true`, `closureEligible=true`, 26 etapas —25 aprobadas y Firefox opcional aceptado—, 1.196/1.196 pruebas no-Playwright y Playwright 106 aprobadas + 54 omisiones exactas/160, 0 fallos. Chromium y WebKit obligatorios pasaron; Firefox quedó no disponible en Windows nativo con salida 2. El artefacto mide 41.090 bytes, tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6` y liga inicio, fin y publicación a la huella `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f` de 654 archivos. El [real-stack vigente](../artifacts/real-browser-stack-local.json) aprobó 4/4, limpieza y huellas protegidas, con SHA-256 `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`. Esta evidencia es un cierre de ingeniería del laboratorio, no certificación, pentest ni autorización productiva.

## Objetivos

1. Una iglesia no accede a datos, archivos, eventos, claves ni backups de otra.
2. Una función global no otorga acceso automático al contenido de tenant.
3. Un rol no puede delegar permisos que no posee como delegables.
4. Una respuesta se recibe una sola vez por elector y ronda.
5. Un cierre y un envío concurrentes tienen un resultado inequívoco.
6. Las preferencias no aparecen en logs, telemetría ni reportes nominales.
7. Un volcado ordinario del backend no descifra categorías declaradas E2EE.
8. Las acciones sensibles son reautenticadas, versionadas y auditadas.

## Identidad y sesión

- Invitaciones vinculadas a destinatario y tenant, de un solo uso y con caducidad.
- MFA obligatorio para administradores globales y de tenant antes de ejercer privilegios.
- Passkeys/WebAuthn descubribles como método primario; TOTP como fallback controlado por política.
- Códigos de recuperación de un solo uso, con flujo auditable.
- Cookies `HttpOnly`, `Secure` en TLS y `SameSite` acorde al flujo.
- Protección CSRF en mutaciones basadas en cookie.
- Rotación de sesión después de autenticación y cambios de privilegio.
- Revocación por cierre de sesión, suspensión, cambio sensible o incidente.
- No almacenar tokens de sesión de larga duración en `localStorage`.
- Reautenticación para cambiar administradores, activar recuperación, rotar claves y exportar ampliamente.

El perfil local implementa contraseña Argon2id, passkeys WebAuthn, desafío/enrolamiento TOTP, códigos de recuperación de un solo uso, invitaciones vinculadas a tenant/destinatario con caducidad/consumo/revocación, cookies de sesión y CSRF. El proveedor de identidad corporativo y los controles dependientes de infraestructura productiva continúan siendo decisiones del despliegue; el laboratorio local no debe promoverse como certificación definitiva de identidad.

### Passkeys y experiencia multidispositivo

- La entrada primaria es usernameless: la cuenta se descubre dentro de la credencial y la respuesta pública no varía según exista o no un correo.
- Se exigen credenciales descubribles, presencia y verificación de usuario. El servidor valida firma, challenge, tipo, origen exacto y RP ID mediante `@simplewebauthn/server`; no implementa CBOR/COSE artesanalmente.
- Challenges y tokens de ceremonia son breves, de un solo uso y se conservan únicamente como SHA-256. Clave pública, contador, AAGUID, transports, tipo de dispositivo y estado de backup se guardan; la biometría nunca sale del autenticador.
- En el mismo teléfono o computador se usa la biometría/PIN del sistema. El QR de WebAuthn solo aparece cuando el propio navegador ofrece autenticación entre dispositivos; la aplicación no obliga a escanear un QR para usar el mismo móvil.
- En el laboratorio el origen humano canónico es `http://localhost:3000` y el RP ID es `localhost`; WebAuthn rechaza direcciones IP como RP ID. El acceso por loopback-IP en puertos operativos recibe un 307 absoluto hacia el mapa fijo `localhost`, con path/query y fragmento de navegador preservados, `no-store`, sin cookie y sin confiar en `Host`/`X-Forwarded-Host`; `/healthz` permanece 200 sin redirección. Los cuatro perfiles Playwright comprobaron ese límite y la disponibilidad posterior de passkey, incluidas cabeceras reenviadas hostiles. Producción requiere un dominio DNS definitivo y HTTPS antes del primer enrolamiento.
- Una segunda passkey exige una verificación WebAuthn fresca, de un solo uso y ligada exactamente a la solicitud que inicia el alta. Primera passkey y sustitución desde recuperación restringida conservan una vía explícita.
- El Centro de seguridad permite nombrar/revocar passkeys, revisar/revocar sesiones y cerrar las demás sesiones. La revocación invalida también las sesiones y grants dependientes de la credencial.

### TOTP sin dependencia de un segundo dispositivo

- En móvil, un gesto explícito abre una URI `otpauth:` validada para que el autenticador instalado importe la cuenta sin escanear la misma pantalla.
- En PC, el QR se genera dentro del navegador. Semilla y URI no se envían a un generador remoto, analytics ni almacenamiento persistente.
- La semilla solo se entrega al iniciar la ceremonia breve. Tras recargar, el navegador conserva únicamente la referencia/expiración y puede confirmar con el código ya configurado; el servidor no vuelve a entregar la semilla. Al confirmar/cancelar/expirar deja de estar disponible.
- Los códigos de recuperación se muestran una sola vez, se almacenan con hash resistente y cada código se consume atómicamente una vez.

### Garantía, recuperación y step-up

- Cada sesión registra método, AAL, resistencia a phishing, credencial, expiración absoluta, inactividad y estado de recuperación.
- Un código de recuperación crea `recovery_limited`: sin permisos del tenant, sin grant de clave de contenido y con rutas limitadas a cerrar sesión o registrar un reemplazo.
- Las operaciones protegidas por WebAuthn usan un grant opaco, breve y de un solo uso ligado a identidad, sesión, propósito y hash canónico de método/ruta/cuerpo. Un cambio del cuerpo, ruta, sesión o un replay falla cerrado.
- Cambios de red móvil o user-agent se registran como señales sanitizadas; no se tratan como identidad humana ni expulsan por sí solos una sesión válida. Tokens, expiración, revocación y step-up siguen siendo controles decisivos.
- La política global es el piso; la política del tenant solo puede endurecerla. `monitor` informa brechas de AAL/passkeys/postura privilegiada sin bloquear la transición; `enforce` aplica esos objetivos. Prohibiciones explícitas de método, límites de sesión y verificaciones criptográficas permanecen activas en ambos modos.
- La autenticación de la cuenta y el desbloqueo E2EE son capas distintas. Una passkey abre la sesión; cuando una pantalla necesita contenido cifrado, el cliente aún solicita la contraseña de custodia para desenvolver la clave localmente. La API nunca recibe contenido descifrado.

## Autorización

- Denegación predeterminada.
- Permisos atómicos del dominio; roles son agrupaciones editables dentro de límites seguros.
- Autorización por objeto después de resolver sesión y tenant.
- El derecho de voto proviene del snapshot congelado de electores, no del rol administrativo.
- La UI elimina acciones irrelevantes; la API vuelve a comprobarlas.
- Recursos ajenos responden de forma neutral para evitar enumeración.
- Acceso de soporte: concesión explícita, limitada, revocable y auditada; nunca acceso retroactivo a boletas secretas.

## Aislamiento de tenant

- Base y credencial de ejecución exclusivas por iglesia.
- Plano de control sin padrón, notas, votos o informes del tenant.
- Pools acotados por tenant y versión de credencial.
- Contexto explícito en HTTP, eventos, colas, objetos, caché, reportes y backups.
- Ninguna solicitud ordinaria usa rol de aprovisionamiento o superusuario.
- Pruebas negativas deben alterar ID, ruta, cabecera, cuerpo, sesión, canal en vivo y nombre de objeto.

## Mutaciones electorales

- `Idempotency-Key` único por actor/operación y huella del cuerpo.
- `expectedVersion` para control optimista.
- Restricciones únicas para una recepción efectiva.
- Transacción de cierre que fija conjunto de recibos y criptogramas.
- Servidor confirma recepción solo después del commit.
- Un envío tardío recibe rechazo explícito; no hay éxito optimista.
- Padrón, reglas y candidatos congelados por ronda.
- No se publican conteos por candidato durante la ronda abierta.

## Entrada y archivos

Los controles siguientes se aplican tanto en contratos de servidor como, cuando mejora la experiencia, en el cliente. La importación inspecciona el contenedor XLSX/ZIP, límites de tamaño/compresión/filas, macros, objetos y enlaces externos; no evalúa fórmulas. Las exportaciones neutralizan fórmulas. Las fotos se validan por bytes reales, se decodifican, recortan y recrean en JPEG 512×512 antes del cifrado, con límites antibomba y verificación de que no quede EXIF.

- Esquemas estrictos y rechazo de propiedades inesperadas.
- Consultas parametrizadas.
- Escape contextual y CSP contra XSS.
- Límite de cuerpo, cuotas y rate limiting por identidad/tenant/acción.
- Excel/CSV: no macros, no evaluación de fórmulas o enlaces, límites de descompresión y filas.
- Exportación: neutralizar celdas que comiencen con `=`, `+`, `-`, `@`, tabulador o retorno de carro.
- Fotos: verificar bytes reales, decodificar/recrear, eliminar EXIF, limitar dimensiones/formato/tamaño.
- No descargar URLs arbitrarias de una importación.

## Navegador y cadena de suministro

- CSP con nonces/hashes y sin `unsafe-eval` en producción.
- `frame-ancestors`, `base-uri`, `object-src`, `form-action` y `connect-src` mínimos.
- Dependencias exactas y lockfile; no versiones flotantes en artefactos.
- SBOM, licencias, escaneo de secretos y vulnerabilidades en CI.
- Prohibir analítica que capture formularios, grabación de sesiones y terceros en pantallas con datos descifrados.
- El service worker de producción solo cachea una allowlist pública (favicon/fuente) y estáticos versionados de Next. No intercepta navegación ni rutas `/v1` o `/api`, y admite purga explícita; sus pruebas inspeccionan CacheStorage.

## Auditoría

Registrar: autenticación, invitaciones, permisos, importación, elegibilidad, fases, recibos, escrutinio, publicación, consentimiento, decisiones, exportación, recuperación y operación de tenants.

No registrar: contraseñas, tokens, claves, texto de notas, nombres unidos a preferencias, cuerpos de boleta o contenido descifrado.

La base tenant implementa secuencia y hashes encadenados con permisos de ejecución limitados. Checkpoints Ed25519 y un ledger local separado detectan alteración, borrado, truncamiento, reordenamiento y rollback/restauración en el laboratorio. Ese ledger local demuestra detección, pero no equivale a un ancla WORM físicamente independiente; producción debe exportar/anclar fuera del alcance de la base y del host.

## Gestión de vulnerabilidades

1. Inventario y SBOM por build.
2. Revisión de advisories de runtime, framework, criptografía, parser de archivos y autenticación.
3. Bloqueo de secretos y dependencias críticas/altas pertinentes en CI.
4. Corrección o excepción documentada con propietario, fecha y aceptación de riesgo.
5. Revisión de permisos y pentest antes de producción.

## Evidencia requerida antes de producción

- Repetir la matriz local completa contra el artefacto/infraestructura exactos de producción y conservar resultados firmados.
- E2E de reautenticación con el proveedor de identidad elegido y política institucional de recuperación.
- Inspección de red/HTML/logs de un usuario sin permiso de nota privada.
- Carrera cierre/envío y reintentos concurrentes.
- Revisión independiente del protocolo y código criptográfico.
- Verificación de TLS/HSTS/CSP, procedencia y artefacto reproducible.
- Restauración aislada recurrente con RPO/RTO del entorno real.
- Exportación de auditoría a SIEM/ancla WORM independiente y ensayo de respuesta.
