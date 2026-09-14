# Documentación del producto

Fecha de corte documental: **14 de septiembre de 2026**.

La implementación local está integrada. La ampliación enterprise de autenticación añadió passkeys/WebAuthn, assurance/step-up, recuperación restringida, gestión de credenciales y sesiones, políticas por tenant y alta TOTP adecuada para teléfono o PC. El Centro de seguridad actual permite editar métodos admitidos y límites de sesión, además del rollout/AAL/passkeys/postura privilegiada; conserva como pisos inmutables la verificación de usuario y la resistencia al phishing, y presenta la matriz de requisitos por acción en solo lectura. La ceremonia mutable autorizada aprobó 4/4 pruebas reales —incluida una passkey residente con verificación de usuario— con cleanup exacto y sin alterar control, Demo u Ozama. El cierre integral actual incorpora el endurecimiento posterior; el pase del 13-09, continuidad, anclaje y reinicio anteriores se preservan como evidencia histórica separada. Esta documentación usa estados acotados:

- **Implementado:** existe código, contrato o migración identificable.
- **Verificado localmente:** existe una prueba reproducible ejecutada dentro del laboratorio descrito.
- **Verificado en el cierre actual:** el comportamiento está incluido en el artefacto integral verde de la huella fuente indicada.
- **Pendiente externo:** requiere autoridad eclesiástica, asesoría jurídica, proveedor, infraestructura productiva o auditor independiente.

Ninguna página constituye certificación institucional, jurídica, WCAG, OWASP ASVS o criptográfica.

## Foto actual

- Pila local: web, API y worker sobre PostgreSQL 18 aislado en `127.0.0.1:55432`.
- Datos: el fixture fuente y el estado persistente de Demo coinciden en 180 miembros/150 elegibles. El cierre actual confirmó `pass=true`, `mismatchCount=0`, control 26/26 con cabeza `026_invitation_enrollment_recovery_qualification.sql` y Demo/Ozama 38/38 hasta `036_transactional_invitation_grantor_lock.sql`; Ozama permanece `pending_activation`, con 47 tablas operativas y 0 filas. Los drills históricos de ambos tenants preservaron exactamente al vecino.
- Funciones: passkey primaria, TOTP de fallback, recuperación limitada, step-up ligado a la operación, políticas por tenant con readiness transaccional, invalidación de autorizaciones anteriores y reconciliación inmediata de sesiones, acceso local, miembros/importación Web Worker/fotos, ciclos/sesiones/rondas, custodia y escrutinio, asignaciones, organigrama, analítica trazable, trece reportes con corrección lineal, auditoría y continuidad local. La API sólo confía en forwarding headers desde la allowlist explícita de proxies; producción exige una lista no vacía. Véase [Autenticación enterprise](authentication.md).
- Contrato fuente actual: OpenAPI 3.1 con 149 paths, 165 operaciones y 278 esquemas. Los censos 129/142/235 y 142/157/264 pertenecen a cortes históricos anteriores.
- Persistencia fuente y aplicada: 26 archivos de migración del plano de control y 38 archivos tenant, hasta `026_invitation_enrollment_recovery_qualification.sql` y `036_transactional_invitation_grantor_lock.sql` respectivamente; el cierre actual reconcilió 26/26 y 38/38 sin desajustes.
- Carga: 10 tenants × 50 participantes × 10.000 miembros; el artefacto sanitizado de API/SSE esquema 3 concluyó `overallPass: true` sin tocar control, Demo ni Ozama. Una medición Chromium complementaria ejercitó descarga, descifrado, índice y búsqueda de 10.000 sobres sintéticos en memoria, además de métricas de la página pública de acceso; no ejercitó la ruta, componentes, API ni PostgreSQL reales de Members.
- Idiomas y vista estrecha: 2.404 claves por locale con paridad exacta ES/EN/FR. Una inspección CUA local posterior al arreglo confirmó cero desbordamiento horizontal a 320 px en los tres idiomas y manifiestos localizados; la revisión lingüística institucional y la evaluación WCAG humana permanecen externas.
- Catálogo: la revisión canónica de contenido es `2025.1.0` y contiene 29 departamentos y 67 oficinas/cargos. El paquete institucional permanece `draft`; la aprobación denominacional/regional para Ozama sigue pendiente y externa.
- Cadena de suministro actual: el cierre regeneró SBOM, inventario de licencias, audit y escaneos de fuente/entrega sobre la huella congelada. El resultado verde se limita a las políticas y detectores automatizados declarados; no sustituye firma de procedencia ni revisión jurídica o de seguridad independiente.

> **CIERRE LOCAL INTEGRAL ACTUAL: APROBADO.** [`verify-local-final.json`](../artifacts/verify-local-final.json), ejecutado de `2026-09-14T10:56:10.4065404Z` a `11:04:21.4060919Z`, registra `result=passed`, `overallPass=true`, `closureEligible=true`, 26 etapas —25 aprobadas y Firefox aceptado como opcional—. Pasaron 1.196/1.196 pruebas no-Playwright —39 verificador, 41 dominio, 31 E2EE, 441 base, 417 API y 227 web—, más Playwright 106 aprobadas + 54 omisiones exactas allowlisted = 160 planificadas y 0 fallos. Los proyectos cerraron `desktop-chromium-es` 40/40 y `mobile-chromium-es`, `mobile-small` y `mobile-webkit-fr` con 22 pruebas ejecutadas + 18 omisiones gobernadas cada uno. Firefox quedó opcional no disponible en Windows nativo con salida 2. El archivo mide 41.090 bytes, tiene SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6` y congeló 654 archivos con la misma huella en inicio, fin y publicación: `e524c0fc3333c5ced3ec6faa9b1d4092eade559309386ff76a325442854ace8f`.

> **REAL-STACK ACTUAL: APROBADO.** [`real-browser-stack-local.json`](../artifacts/real-browser-stack-local.json) registra 4/4 escenarios entre `2026-09-14T10:55:31.681Z` y `10:55:43.495Z`, huellas protegidas sin cambios y cleanup con cero bases/roles efímeros. Mide 3.953 bytes y su SHA-256 es `787d64b3a5ca0fc8d48a14559b76ee8dae6805a2d44b1776cebf7945872c8d3b`.

> **HISTORIAL SEPARADO.** El pase del 13-09 con SHA-256 `532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a` vive en [`history/verify-local-final.sha256-532af….json`](../artifacts/history/verify-local-final.sha256-532af0a43a374705a1e3f3a2020c35bc22940fe568f923068de06bca0a182c7a.json), no en el alias mutable actual. [`closure-postcheck-final.json`](../artifacts/closure-postcheck-final.json) continúa como suplemento histórico ligado a evidencia anterior, no como evidencia del cierre actual. Véase [verification.md](verification.md).

La fuente incluida en el cierre actual abarca serialización de altas/revocaciones/límites de sesión, readiness tenant-wide, reconciliación de sesiones, invalidación contada de ceremonias WebAuthn, challenges TOTP y grants obsoletos, throttle por identidad y agregados antiabuso, preflight/clamping al cambiar de tenant, baseline global inmutable, confianza de proxy por CIDR explícito, recuperación gobernada del administrador inicial y fronteras transaccionales de invitación. Es un cierre de ingeniería local, no una certificación productiva o “Fortune 500”.

## Índice

- [Arquitectura](architecture.md)
- [Decisiones de arquitectura](adr/README.md)
- [Matriz normativa](normative-matrix.md)
- [Seguridad](security.md)
- [Autenticación enterprise: operación y despliegue](authentication.md)
- [Modelo de amenazas](threat-model.md)
- [Cifrado](encryption.md)
- [Ciclo de claves](key-lifecycle.md)
- [Privacidad](privacy.md)
- [Contratos de API y eventos](api/README.md)
- [Centro de reportes](reports.md)
- [Sistema de diseño](design-system.md)
- [Accesibilidad](accessibility.md)
- [Dependencias y licencias](dependencies.md)
- [Operación y continuidad](operations.md)
- [Rendimiento local](performance.md)
- [Costos](costs.md)
- [Roles y permisos](roles.md)
- [Guía del administrador global](guides/platform-administrator.md)
- [Guía del administrador de iglesia](guides/church-administrator.md)
- [Guía del secretario](guides/secretary.md)
- [Guía del miembro de junta](guides/committee-member.md)
- [Matriz de aceptación](acceptance-matrix.md)
- [Verificación local](verification.md)
- [Limitaciones conocidas](known-limitations.md)

## Dependencias externas de salida

Aunque el cierre local resulte verde, siguen bloqueando producción:

1. jurisdicción, suplementos y aprobación denominacional para Ozama;
2. base jurídica, privacidad, residencia, transferencias y retención;
3. traducciones oficiales y permisos de marca/manuales;
4. revisión criptográfica, seguridad y pentest independientes;
5. evaluación manual con lectores de pantalla, teclado, zoom y dispositivos reales;
6. dominio RP WebAuthn definitivo, DNS, TLS/HSTS, reverse proxy con allowlist exacta de IP/CIDR y pruebas de cadena de confianza, KMS/HSM, almacenamiento de objetos, correo, observabilidad, backups externos y WORM en infraestructura separada;
7. IdP/SCIM y, si se exige attestation/AAL3, FIDO Metadata Service y autenticadores administrados;
8. pruebas físicas iOS/Android/Windows/macOS y revisión jurídica humana de licencias, avisos y activos del bundle final.

Esas dependencias no son fallos ocultos del comando local: son decisiones y garantías que el repositorio no puede autoaprobar.
