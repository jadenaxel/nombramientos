# Matriz OWASP ASVS

Versión fijada: **OWASP ASVS 5.0.0**, nivel objetivo **L2** para el despliegue de producción. La referencia estable es la publicación oficial de OWASP; los identificadores se escriben como `v5.0.0-x.y.z` para que no cambien de significado cuando aparezcan revisiones posteriores.

Esta matriz es trazabilidad de ingeniería, no una certificación. `Verificado local` significa que existe implementación y evidencia automatizada reproducible en este repositorio. `Parcial` significa que hay controles implementados, pero falta una parte del requisito o su validación en el entorno de producción. `Externo` identifica controles que no pueden cerrarse con un laboratorio local.

## Controles con evidencia local

| ASVS 5.0.0 | Control aplicado | Evidencia principal | Estado |
|---|---|---|---|
| `v5.0.0-1.2.4` | Consultas PostgreSQL parametrizadas | stores de `packages/database/src`; pruebas de integración DB/API | Verificado local |
| `v5.0.0-1.2.10` | Neutralización de fórmulas en CSV/XLSX | política de reportes y `apps/api/test/report-policy.test.ts` | Verificado local |
| `v5.0.0-2.2.1`, `v5.0.0-2.2.2` | Validación positiva y autoritativa en el servidor | contratos Zod, pruebas de contrato API | Verificado local |
| `v5.0.0-2.3.1`, `v5.0.0-2.3.3` | Orden de estados y transacciones atómicas del proceso electoral | `packages/domain/test`; pruebas `core-workflow*` y concurrencia | Verificado local; se repite tras reconstrucción final |
| `v5.0.0-2.4.1` | Límites de solicitudes y protección antiabuso | middleware de API y pruebas de contratos | Verificado local |
| `v5.0.0-3.3.2`, `v5.0.0-3.3.4` | Cookie de sesión `SameSite`/`HttpOnly` | `apps/api/src/security.ts`, pruebas de autenticación | Verificado local |
| `v5.0.0-3.4.2` | CORS por lista de orígenes | `apps/api/src/security.ts`, pruebas de rutas | Verificado local |
| `v5.0.0-3.4.3`–`v5.0.0-3.4.6` | CSP con nonce, `nosniff`, política de referente y bloqueo de marcos | configuración web y pruebas HTTP/navegador | Verificado local; TLS/HSTS se valida en producción |
| `v5.0.0-3.5.1`, `v5.0.0-3.5.3` | CSRF ligado a sesión y métodos mutantes | seguridad API y pruebas de contratos | Verificado local |
| `v5.0.0-5.1.1`, `v5.0.0-5.2.1`, `v5.0.0-5.2.2`, `v5.0.0-5.2.6` | Fotos limitadas, tipo real por bytes mágicos, decodificación/recreación y límite de píxeles | `photo-contract`, `photo-client`, pruebas DB/API/web | Verificado local |
| `v5.0.0-6.1.1` | Defensa documentada y limitada contra fuerza bruta | autenticación/API y `docs/security.md` | Parcial: falta calibración con tráfico real |
| `v5.0.0-6.5.3`–`v5.0.0-6.5.5` | Secretos MFA CSPRNG y TOTP con vigencia de 30 segundos | `mfa-store`, servicio/rutas de autenticación, prueba UI | Verificado local |
| `v5.0.0-8.3.1`, `v5.0.0-8.4.1` | Autorización de servidor y aislamiento por tenant | permisos de dominio, DB por tenant, pruebas negativas y de aislamiento | Verificado local; se repite a escala 10 tenants |
| `v5.0.0-11.1.1`, `v5.0.0-11.1.2` | Ciclo de claves e inventario criptográfico | `docs/encryption.md`, ADR E2EE y `packages/e2ee` | Parcial: requiere revisión criptográfica independiente |
| `v5.0.0-11.2.1`, `v5.0.0-11.2.3` | Primitivas de plataforma con al menos 128 bits de seguridad | Web Crypto/Node crypto; pruebas de vectores y ceremonia | Verificado local; no certificado externamente |
| `v5.0.0-11.3.2`–`v5.0.0-11.3.4` | AES-256-GCM, AAD y nonces únicos | `packages/e2ee`, cifrado de DB y pruebas de manipulación | Verificado local |
| `v5.0.0-11.4.2`, `v5.0.0-11.4.4` | Hash/KDF intensivo para contraseña y derivación de claves | autenticación, backup de claves y pruebas | Verificado local; parámetros sujetos a revisión periódica |
| `v5.0.0-11.5.1` | Tokens y material aleatorio mediante CSPRNG | módulos auth/E2EE e invitaciones | Verificado local |
| `v5.0.0-13.2.2`, `v5.0.0-13.2.3` | Cuentas de servicio sin credenciales predeterminadas y con privilegios mínimos | bootstrap local, grants y aprovisionador | Verificado local; producción debe usar secretos propios |
| `v5.0.0-14.2.8` | Eliminación de metadatos de fotos mediante recreación de imagen | editor/cliente de fotos y pruebas de contenido | Verificado local |
| `v5.0.0-14.3.1`–`v5.0.0-14.3.3` | Limpieza de sesión/tenant, `no-store` y ausencia de datos sensibles en almacenamiento persistente | shell web, service worker allowlist, pruebas PWA/E2E | Verificado local; inspección final pendiente |
| `v5.0.0-15.1.2` | SBOM de dependencias transitivas | `scripts/generate-sbom.mjs`, `artifacts/sbom.cdx.json` | Verificado local; se regenera al cierre |
| `v5.0.0-16.2.5`, `v5.0.0-16.3.1`–`v5.0.0-16.3.4` | Redacción de datos y auditoría de eventos de seguridad | auditoría DB/API y pruebas de historial | Verificado local |
| `v5.0.0-16.4.2` | Cadena inmutable, checkpoints firmados y detección de alteración | `audit-anchors*`, prueba de alteración/borrado/reorden/rollback | Verificado en laboratorio; ancla WORM externa pendiente |
| `v5.0.0-16.5.1`, `v5.0.0-16.5.3` | Errores neutros y fallo cerrado | envolvente API y pruebas negativas | Verificado local |

## Controles que dependen del despliegue o de terceros

| ASVS 5.0.0 | Cierre requerido | Estado honesto |
|---|---|---|
| `v5.0.0-3.3.1`, `v5.0.0-3.3.3`, `v5.0.0-3.4.1` | Host HTTPS definitivo, cookies con prefijo `__Host-` y HSTS de al menos un año | Externo al modo local HTTP |
| `v5.0.0-5.4.3` | Motor antivirus administrado para cualquier archivo no recreado por la aplicación | Externo; las fotos aceptadas se decodifican y recrean |
| `v5.0.0-11.2.2` | Ensayo formal de cripto-agilidad y migración post-cuántica | Parcial; inventario existe, auditoría independiente pendiente |
| `v5.0.0-12.3.1`–`v5.0.0-12.3.4` | TLS extremo a extremo con CA y políticas del entorno productivo | Externo; el laboratorio está restringido a loopback |
| `v5.0.0-13.1.4` | Calendario institucional de rotación de secretos | Requiere decisión operativa del propietario |
| `v5.0.0-14.2.7` | Calendario legal/institucional de retención y borrado | Requiere jurisdicción y aprobación del propietario |
| `v5.0.0-15.1.1`, `v5.0.0-15.2.1` | SLA de remediación y monitoreo continuo de vulnerabilidades | Requiere operación continua; auditoría puntual se ejecuta al cierre |
| `v5.0.0-16.4.3` | Exportación de logs a SIEM separado y ancla WORM | Externo; el laboratorio demuestra integridad y detección, no separación física |

## Criterio de cierre

El producto no se describirá como “ASVS certificado” sin una evaluación independiente que cubra todos los requisitos L2 aplicables en el entorno productivo. El cierre local exige reconstrucción limpia, todas las suites automatizadas, pruebas negativas de autorización y tenant, inspección de almacenamiento/navegador, SBOM y auditoría de dependencias reproducibles. Los controles marcados `Externo` permanecen requisitos de salida a producción aunque el software local esté completo.

Fuente normativa: [OWASP Application Security Verification Standard 5.0.0](https://owasp.org/www-project-application-security-verification-standard/).
