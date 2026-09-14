# Modelo de amenazas

Fecha de corte: **11 de septiembre de 2026**.

## Alcance y garantías

Plataforma multi-tenant para identidad, padrón, deliberación, propuestas, boletas, escrutinio, recomendaciones, actas/reportes y operación. El laboratorio implementa controles técnicos locales; este modelo no afirma que el despliegue productivo —todavía inexistente— herede automáticamente esas garantías.

No se supone infalible al administrador local/global, custodio, navegador, host, proveedor o persona operadora. El modo multi-custodio confía en cada custodio para abrir boletas durante el recuento.

## Activos

| Activo | Impacto |
|---|---|
| Identidad, membresía y padrón | dato religioso, privacidad y daño personal |
| Elegibilidad, disponibilidad y razones | dignidad, discriminación y decisiones injustas |
| Notas/deliberaciones | confidencialidad crítica |
| Propuestas y boletas | secreto e integridad del proceso |
| Recibos, manifiestos y agregados | integridad y capacidad de conciliación |
| Claves tenant/dispositivo/custodio | acceso masivo o pérdida irreversible |
| Roles, snapshots y estados | autorización e historia institucional |
| Fotos, actas y reportes | privacidad, reputación y retención |
| Auditoría, checkpoints y recibos | detección de manipulación/rollback |
| Backups y secretos operativos | alcance sistémico |

## Actores

- usuario legítimo curioso o malicioso;
- administrador local abusivo o comprometido;
- administrador global u operador de infraestructura;
- custodio aislado o custodios coludidos;
- atacante externo y bot de credenciales;
- proveedor de identidad/correo/hosting comprometido;
- dispositivo perdido, infectado o compartido;
- servidor que entrega JavaScript malicioso;
- error humano de importación, transición, cierre, recuperación o restauración;
- dependencia de software o artefacto de build comprometido.

## Fronteras

1. navegador ↔ web;
2. web ↔ API;
3. API ↔ plano de control;
4. resolvedor ↔ credencial/base tenant;
5. worker privilegiado ↔ plano de control/aprovisionamiento;
6. custodio ↔ claves públicas, criptogramas, manifiesto y atestación;
7. backup/restore ↔ llaves y scratch local;
8. base tenant ↔ ledger/recibo local de auditoría;
9. infraestructura futura ↔ KMS, objetos, correo, observabilidad y WORM externos.

Las fronteras 1–8 tienen implementación local. La frontera 9 sigue externa.

## Registro de amenazas

| ID | Amenaza | Control local observado | Riesgo residual / cierre |
|---|---|---|---|
| T-01 | Alterar ID/query/header/body/cookie para cruzar tenant | sesión autoritativa, base/rol propio, 404 neutral y pruebas HTTP | repetir tras proxy/objetos/caché productivos |
| T-02 | Reusar pool o caché entre iglesias | pool por tenant+versión, sesión rotada, limpieza cliente; cruces DB/HTTP de carga | inspección multiinstancia y cache externo |
| T-03 | Rol local concede permisos globales o autoescalada | catálogo atómico, límite delegable, invalidación y pruebas live | revisión independiente de todas las rutas futuras |
| T-04 | Admin global obtiene claves/contenido tenant | procesos/roles separados, API global sin secretos tenant, grants separados de RBAC | separación OS/infra y ceremonia institucional |
| T-05 | Reintento/dos pestañas crean doble envío | idempotencia, unicidad, commit antes del recibo; carrera HTTP/PostgreSQL AC-15 | ensayo en topología distribuida |
| T-06 | Cierre compite con último envío o doble cierre | bloqueo/versionado transaccional; tres pruebas live AC-16 | replica/colas y relojes productivos |
| T-07 | Conteos parciales filtran preferencias | SSE allowlist, participación sin preferencia, agregados solo publicados | correlación temporal en comités pequeños |
| T-08 | Servidor sustituye llave pública | huellas, snapshots versionados, challenge y comparación fuera de banda | la API no autentica identidad humana; ceremonia externa |
| T-09 | Replay/context confusion | AAD exacto con tenant/ciclo/ronda/versión/purpose/hashes | auditoría criptográfica |
| T-10 | Boleta corrupta/ilegal altera recuento | HPKE autenticado, esquema/cardinalidad/duplicados/abstención validados localmente | política institucional de anulación |
| T-11 | Custodios reciben conjunto incompleto | manifiesto fijo, hash y atestaciones coincidentes de identidades distintas | no equivale a verificabilidad E2E académica |
| T-12 | XSS/JS malicioso roba claro | escape, CSP/headers, dependencias inventariadas, sin analytics | servidor/extensión/dispositivo comprometidos quedan dentro del TCB |
| T-13 | Dispositivo perdido conserva claves o una sesión robada intenta escribir ciphertext ilegible | bloqueo, grant/revocación/rotación, generación activa fijada dentro de la transacción de contenido | no borra copias extraídas; la sesión HTTP se liga a identidad, no prueba posesión del dispositivo/grant que originó cada write |
| T-14 | Fórmula maliciosa en exportación | neutralización CSV/XLSX y tests | matriz manual Excel/LibreOffice |
| T-15 | Foto contiene EXIF, formato o bomba | decode/re-encode, límites, sin nombre/EXIF en DB/eventos, pruebas unitarias/live/E2E | antivirus/objetos productivos pendientes |
| T-16 | Logs/reportes filtran notas o votos | allowlist de errores/eventos, redacción, proyección por audiencia | revisar proxy, APM, SIEM y soporte reales |
| T-17 | Se reescribe auditoría y sus hashes | cadena tenant, checkpoints/anclajes Ed25519 y tamper drills | ledger/llaves locales no son WORM |
| T-18 | Restaurar backup antiguo oculta eventos | backup autenticado, manifest y restore scratch; comparación con cabeza | exige recibo WORM externo al backup/host |
| T-19 | Seed Demo afecta Ozama | allowlist de UUID/tipo, migraciones idénticas y seed audit | control de cambio y revisión continua |
| T-20 | Invitación/correo revela o concede de más | token aleatorio una vez, hash/expiración/revocación, roles exactos y MFA | proveedor de correo y canal humano pendientes |
| T-21 | Artefacto de reporte se cambia o cruza | ciphertext, manifest, hashes, tamaños y AAD exacto; scope tipo/audiencia | firma/sello institucional si se requieren |
| T-22 | Backup/llave local quedan accesibles a otro principal | rutas confinadas, ACL current-user+SYSTEM, fallo cerrado | administrador del host y recuperación externa |
| T-23 | Dependencia comprometida o licencia incompatible | lockfile, resolución transitiva revisada, SBOM, scanner, compatibilidad XLSX y audit | procedencia/firma y revisión jurídica humana del bundle pendientes |

## Metadatos observables

E2EE no oculta al servidor identidad autenticada, tenant/membresía, IP, user agent, tiempo, tamaño/frecuencia, fase, número de recibos, estado de cola ni destinatarios criptográficos. En un comité pequeño, correlacionar presencia y tiempo puede revelar información. No se promete anonimato ni resistencia a coacción.

## Abusos de UX que se tratan como seguridad

- presentar “recomendado” o “presentado” como “elegido”;
- cambiar denominador para mostrar 100 %;
- tratar ausencia como abstención;
- sustituir silenciosamente una selección al llegar al máximo;
- precargar nota restringida y ocultarla con CSS;
- afirmar “recibido” antes del commit;
- reenviar un borrador offline después del cierre;
- fusionar homónimos por nombre;
- mostrar acciones que el permiso real hará fallar;
- reutilizar métricas actuales al seleccionar un ciclo histórico.

## Dependencias externas

- taller de amenazas con responsables de Ozama;
- revisión legal/privacidad de datos religiosos y transferencias;
- auditoría criptográfica y pentest independientes;
- diseño de confianza para JS servido, CSP/SRI y procedencia firmada;
- proveedores de identidad/correo/objetos/observabilidad;
- KMS/HSM y separación de operadores;
- anclaje WORM fuera del host y restore que consulte esa cabeza;
- revisión después de seleccionar red, proxy, TLS y despliegue.

El modelo debe actualizarse ante cada cambio de frontera, proveedor, algoritmo, flujo electoral o requisito institucional.
