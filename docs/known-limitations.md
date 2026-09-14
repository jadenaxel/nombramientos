# Limitaciones conocidas

Fecha de corte: **14 de septiembre de 2026**. Esta lista no autoriza producción y no debe vaciarse solo porque el laboratorio local resulte verde. El modelo, configuración y operación correspondientes están en [Autenticación enterprise](authentication.md).

## Institucionales y normativas

- No se han confirmado la asociación/misión, unión, división ni suplementos territoriales aplicables a Iglesia Adventista Ozama.
- La revisión canónica del catálogo es `2025.1.0`, pero el estado institucional del paquete continúa `draft` hasta que autoridades competentes validen jurisdicción, suplementos y aplicabilidad para Ozama.
- Las traducciones ES/EN/FR no son traducciones oficiales del manual ni han recibido revisión lingüística institucional completa.
- No existe aval, patrocinio o certificación documentada de la Asociación General.
- El uso de marca, símbolos, manuales, extractos y traducciones debe aprobarse por separado de las licencias de software.

## Jurídicas y privacidad

- Responsable, base jurídica, residencia, transferencias, retención y legislación aplicable a datos religiosos no están aprobados.
- Las políticas de retención incluidas son propuestas de ingeniería, no plazos legales.
- Consentimiento/autorización de fotografías, información de disponibilidad y canales de derechos siguen pendientes.
- La retención, rectificación y eventual supresión de cualificaciones append-only no tienen todavía una política jurídica aprobada. E2EE protege título/emisor frente al servidor, pero tipo, estado, fechas, versión y revisor siguen siendo metadatos visibles para el servicio y los principales autorizados.
- Proveedores de identidad, correo, hosting, objetos, backups, observabilidad y soporte no están seleccionados ni evaluados.
- No deben cargarse datos reales de Ozama hasta cerrar estas decisiones.

## Seguridad y criptografía

- No existe auditoría criptográfica independiente ni pentest.
- Passkeys/WebAuthn están implementadas y el escenario real Chromium verifica alta, credencial residente/UV, AAL2 técnico, login, replay fail-closed, step-up y revocación. Esto no es certificación FIDO/NIST ni demuestra AAL3. Faltan FIDO Metadata Service, política AAGUID/attestation, autenticadores administrados y gobierno operativo si se pretende una garantía superior.
- Las passkeys locales están ligadas al RP ID `localhost`. No pueden migrarse por configuración al dominio productivo: antes de producción debe fijarse un dominio RP definitivo con DNS/TLS/HSTS y enrolarse nuevas credenciales.
- TOTP sigue disponible sólo como fallback/transición configurable y no es resistente a phishing. Los recovery codes son de un uso y abren únicamente una sesión `recovery_limited`; su operación segura todavía depende de que la organización defina custodia, soporte e identidad humana fuera de banda.
- La remediación de contraseñas de invitación 019-era es intencionalmente conservadora: sólo elimina una credencial cuando la policy histórica puede demostrarse. Una fila ambigua hace fallar toda la migración para evitar destruir una contraseña legítima; resolver un caso real ambiguo exigiría expediente, análisis y una migración compensatoria específica, no un override manual.
- La matriz de asignación de roles de sistema es una decisión técnica migration-owned y actualmente sólo habilita a `CHURCH_ADMIN` para los seis roles admitidos. Evita derivar gobierno desde permisos operativos, pero no sustituye una política institucional aprobada de separación de funciones, doble control o recertificación. La pérdida de autoridad revoca invitaciones abiertas y los locks cierran carreras locales; el offboarding productivo sigue dependiendo de IdP/SCIM y operación humana.
- No hay IdP corporativo OIDC/SAML, aprovisionamiento SCIM ni integración con MDM. La política local no sustituye altas/bajas, separación de funciones y recertificación institucional de identidades.
- Autenticarse con passkey no desbloquea por sí solo el vault E2EE: las áreas con contenido cifrado pueden volver a pedir la contraseña de custodia para desenvolver la clave en el navegador. No se implementó WebAuthn PRF/key wrapping portable.
- El Centro de seguridad edita rollout/AAL/cantidades/postura privilegiada, los toggles de contraseña/TOTP/recovery/passkeys sincronizadas y los límites de sesiones activas/inactividad/vida absoluta/TTL de step-up. No es un editor irrestricto: los pisos de verificación de usuario y resistencia al phishing aparecen activados pero deshabilitados para edición, y la matriz de requisitos por acción es deliberadamente de solo lectura.
- La fuente ya fija como inmutables el tipo de dispositivo reportado por el autenticador y el bit WebAuthn BE: base y store rechazan inconsistencias/cambios entre ceremonias, y UV se evalúa por assertion. Esto no autentica la cadena de attestation ni certifica el firmware, sistema operativo, navegador o sincronización del proveedor; FIDO Metadata Service, dispositivos administrados, matriz física y revisión independiente siguen pendientes.
- La custodia implementada es HPKE multi-destinatario, no criptografía umbral: cada custodio congelado puede abrir su copia completa.
- Dos atestaciones coincidentes y un manifiesto fijo aportan conciliación local, pero no prueban verificabilidad electoral E2E en el sentido académico.
- No se promete anonimato absoluto, resistencia a coacción, secreto frente a custodios coludidos ni protección ante JavaScript malicioso servido por un backend comprometido.
- Un dispositivo, navegador o extensión comprometidos pueden leer contenido visible/descifrado. Las capturas o copias de un destinatario legítimo no pueden revocarse retroactivamente.
- La sesión HTTP identifica a la persona, pero no está ligada criptográficamente a un `deviceId`. El guard de escrituras E2EE exige una generación vigente y que la identidad conserve al menos un grant y dispositivo activos, pero no demuestra que cada petición provenga físicamente de ese dispositivo. Revocar un grant y rotar evita que ese dispositivo abra claves futuras; una sesión comprometida de la misma identidad todavía puede enviar ciphertext opaco o corrupto si otro grant suyo sigue activo. El cliente autorizado detectará el fallo al autenticar el sobre, pero el servidor no puede validar su plaintext.
- La autenticidad humana de huellas/llaves requiere ceremonia y canal independiente supervisados.
- La seguridad de claves no extraíbles en IndexedDB depende de navegador, sistema operativo y dispositivo; producción necesita política y hardware aprobados.
- El acceso histórico depende de que algún administrador conserve un grant `retired` válido y su clave privada local. Un dispositivo incorporado después de rotar recibe historia sólo mediante una delegación explícita, posterior al grant actual y confirmada por generación; no hay backfill automático. La UI muestra cobertura parcial reanudable —incluido después de rate limit—, pero ni el llavero ni la delegación reconstruyen claves perdidas. El recifrado masivo continúa siendo un flujo operacional separado.
- El ledger local de auditoría es append-only por convención de la herramienta y ACL, no WORM. Un administrador del host que controle llaves, ledger y recibos puede destruir la evidencia local.
- El backup local usa una llave exportable en disco. No sustituye KMS/HSM, separación de funciones, retención bloqueada ni recuperación externa.
- “ASVS 2” y “WCAG 2.2 AA” son objetivos, no certificaciones.

## Producto local

- El flujo funcional local está conectado y pertenece al cierre integral vigente. [`verify-local-final.json`](../artifacts/verify-local-final.json), ejecutado de `2026-09-14T10:56:10.4065404Z` a `11:04:21.4060919Z`, registra `result=passed`, `overallPass=true`, `closureEligible=true`, 26 etapas —25 aprobadas y Firefox opcional aceptado—, 1.196/1.196 pruebas no-Playwright y 160 resultados Playwright —106 aprobados, 54 omisiones exactas allowlisted y 0 fallos—. Chromium/WebKit obligatorios quedaron verdes. El archivo mide 41.090 bytes, tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6` y liga inicio, fin y publicación a la misma huella de 654 archivos: `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f`. El [real-stack vigente](../artifacts/real-browser-stack-local.json), de `2026-09-14T10:55:31.681Z` a `10:55:43.495Z`, aprobó 4/4, cleanup sin residuos y huellas protegidas sin cambios; mide 3.953 bytes y tiene SHA-256 `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`. Esto cierra el alcance automatizado local, no las dependencias externas ni una certificación productiva. Véase [verification.md](verification.md).
- Algunas pruebas Playwright mutables solo corren una vez en Chromium para no corromper el fixture; la matriz multiengine no repite todas las mutaciones en todos los motores.
- En este host, Firefox Playwright no inicia por el error nativo de Windows `WINDOWS_NATIVE_SPAWN_UNKNOWN`. El preflight conservó Chromium y WebKit como obligatorios y registró Firefox como `accepted-optional` con salida 2; no existe evidencia Firefox válida para este corte.
- Docker CLI/Engine no está disponible en este host. La ruta de contenedores tiene contratos y validación estática, no evidencia de build, arranque o healthchecks reales.
- El correo es un canal manual/local: no existe entrega por proveedor, rebote, reputación o recuperación productiva.
- El worker conectado procesa aprovisionamiento. No existe broker distribuido para outbox, correo, objetos o jobs generales.
- SSE funciona en una instancia local y tiene reanudación/filtrado; no se ha ensayado detrás de balanceador, en despliegue multiinstancia, con WAN/pérdida real ni backpressure de producción.
- La API ignora forwarding headers salvo para peers incluidos en `API_TRUSTED_PROXY_CIDRS`, rechaza wildcard y exige una allowlist no vacía en producción. No hay reverse proxy/balanceador productivo desplegado en este laboratorio: todavía deben validarse su CIDR real, cadena de hops, TLS, rotación de infraestructura y comportamiento de rate limiting en esa topología.
- La frontera local de navegador está endurecida alrededor de `localhost`: 307 absoluto server-side desde loopback-IP sólo en puertos operativos conocidos hacia un destino fijo, path/query y fragmento de navegador preservados, `no-store`, sin `Set-Cookie`, `/healthz` no redirigido, Origin exacto en emisores de cookie y gate del bundle contra API 127. Los cuatro perfiles Playwright la comprobaron, incluso con cabeceras reenviadas hostiles y passkey disponible tras llegar al origen canónico. Es una política de laboratorio, no una topología productiva. Deben definirse y probarse el dominio RP HTTPS definitivo, CORS/cookies same-site, TLS/HSTS, proxy/CDN y cachés reales; las passkeys de `localhost` no migran al nuevo RP ID.
- Fotografías se almacenan como bytes normalizados y cifrados en PostgreSQL local. No hay almacén de objetos externo, CDN, escaneo antivirus administrado ni políticas de lifecycle productivas.
- Los trece reportes se generan en navegador y el servidor conserva artefactos cifrados, pero falta una evaluación semántica/manual exhaustiva de cada combinación de tipo, filtro, locale, audiencia, volumen extremo y PDF accesible.
- Las correcciones de reportes conservan una supersesión lineal inmutable y razones normalizadas; no resuelven por sí mismas obligaciones legales de rectificación, supresión o retención, que dependen de la jurisdicción aplicable.
- El PDF no es PDF/UA etiquetado. XLSX y CSV no garantizan por sí solos accesibilidad documental.
- La búsqueda de nombres depende de descargar/descifrar e indexar en el navegador autorizado. La sonda Chromium local sobre 10.000 sobres sintéticos en memoria observó búsqueda p95 de 4,0 ms, máximo de 4,5 ms y brecha máxima de frame de 16,7 ms; no ejercitó la ruta ni componentes reales de Members, API operativa o PostgreSQL. Es un ensayo único de laboratorio, no garantía sobre otros equipos o navegadores.
- El OpenAPI fuente actual tiene 149 paths, 165 operaciones y 278 esquemas; no existe todavía cliente externo generado ni validación independiente exhaustiva de todas las respuestas.
- No hay instalador de producción, actualización automática, rollback de aplicación o migración blue/green.

## Datos y operación

- El clúster local aislado usa `127.0.0.1:55432`; no representa TLS, disponibilidad, replicación, failover o administración productiva.
- El fixture fuente de Demo contiene solo datos sintéticos y define 180 miembros/150 elegibles. El cierre vigente confirmó `pass=true`, `mismatchCount=0`, control 26/26 con cabeza `026_invitation_enrollment_recovery_qualification.sql`, Demo 180/150 y 38/38 migraciones tenant con cabeza `036_transactional_invitation_grantor_lock.sql`; también confirmó Ozama `pending_activation`, 38/38 migraciones y sus 47 tablas operativas vacías. Todos los conteos de drift, backlog y discrepancia quedaron en cero. Esto reconcilia el estado persistente del corte, pero debe repetirse después de cualquier cambio o migración relevante y no representa disponibilidad, failover ni administración productivos.
- El ensayo de backup/restauración mide un dataset local pequeño; no demuestra RPO ≤ 15 min o RTO ≤ 4 h bajo volumen, cifrado externo, objetos y fallos productivos.
- El checkpoint/anclaje local no se publica fuera del host ni usa llaves KMS/HSM no exportables.
- La ceremonia local final verificó 1274 eventos, 5 checkpoints y 5 anclas —secuencia 5— y detectó las 5/5 manipulaciones del drill sin escrituras a base; sigue siendo una emulación de desarrollo en el mismo host, no WORM ni una cabeza externa independiente.
- No hay SIEM, métricas centralizadas, paging, SLO ni pruebas de desastre de infraestructura.
- La prueba AC-37 usa diez listeners Fastify loopback para conservar el rate limiter por IP; no reproduce un único endpoint público tras proxy.
- El artefacto de navegador midió LCP, CLS e INP de laboratorio sobre la página pública no autenticada de acceso, además de un pipeline sintético independiente de descarga/descifrado/índice/búsqueda, sobre HTTP loopback y emulación móvil Chromium. No midió la ruta Members real, API/PostgreSQL, TLS, WAN, pérdida, proxy, escalamiento horizontal, hardware móvil físico ni percentiles de usuarios reales (RUM/field Core Web Vitals).

## Cadena de suministro

- El SBOM no está firmado y no incluye procedencia/SLSA del artefacto desplegable.
- `pnpm audit` es una foto puntual de advisories; un resultado verde no prueba ausencia de vulnerabilidades desconocidas.
- El scanner fuente/supply-chain busca patrones de alta confianza. El scanner de entrega amplía el alcance a artefactos, `dist`, standalone y entradas inspeccionables de ZIP/XLSX/PDF/PNG, pero no ejecuta OCR ni demuestra ausencia absoluta de secretos o PII; el resultado solo significa que no encontró coincidencias según su política y límites declarados.
- La cadena transitiva antigua de ExcelJS fue eliminada mediante una resolución fijada de `unzipper@0.12.5`. El cierre vigente regeneró SBOM, inventario de licencias, audit y escaneos de fuente/entrega para el lockfile y la huella actuales. Sus resultados verdes se limitan a los detectores automatizados declarados; todavía se requiere revisión jurídica humana de licencias, avisos y activos del bundle final.
- Las licencias/notices del bundle final aún requieren revisión jurídica humana.

## Accesibilidad e idiomas

- No se ha completado evaluación manual WCAG 2.2 AA.
- No hay evidencia de recorridos completos con NVDA, VoiceOver o TalkBack ni con dispositivos físicos.
- Faltan recorridos humanos de solo teclado, zoom 200/400 %, texto ampliado, orientación, movimiento reducido y contraste reforzado en todas las superficies.
- Axe solo detecta una parte de los problemas y no constituye conformidad.
- Las rutas y recorridos cubiertos se localizan en ES/EN/FR, pero falta revisión lingüística institucional y de expansión francesa en todas las combinaciones.
- La inspección CUA suplementaria a 320 px detectó y permitió corregir el overflow del bootstrap en ES/EN/FR; su revalidación y la regresión automática quedaron verdes, pero ese chequeo no sustituye personas usuarias, tecnologías de asistencia, zoom ni dispositivos físicos.

## Declaraciones que no se pueden hacer

No describir el producto como:

- “100 % seguro” o “100 % conforme”;
- “listo para producción”;
- “aprobado oficialmente”;
- “anónimo” o “resistente a coacción”;
- “inmutable” sin delimitar la cabeza externa confiable;
- “E2EE verificable completa”;
- “sin vulnerabilidades” o “sin secretos” como garantía absoluta.

La formulación válida es: **alcance local implementado y probado según evidencia fechada, con dependencias externas y riesgos residuales explícitos**.
