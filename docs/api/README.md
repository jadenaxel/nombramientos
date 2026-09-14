# Contrato HTTP y eventos

Fecha de corte: **14 de septiembre de 2026**.

[`openapi.json`](openapi.json) es un contrato OpenAPI 3.1 mantenido en el repositorio. En el corte actual contiene **149 paths, 165 operaciones y 278 esquemas**. Las comprobaciones automáticas validan referencias, componentes críticos y paridad path/método con las rutas Fastify.

El contrato no se genera desde runtime y `v1` todavía no se ofrece como API pública con compatibilidad garantizada ni cliente externo generado.

> **CIERRE_API_FINAL: APROBADO EN LABORATORIO.** El censo estructural 149/165/278, sus referencias y la paridad path/método quedaron incluidos en el cierre `verify:local` de `2026-09-14T10:56:10.4065404Z`–`11:04:21.4060919Z`: API 417/417 en 58 archivos, integración PostgreSQL live, real-stack 4/4, escaneo del delivery y estado persistente verdes. El artefacto autoritativo es [`verify-local-final.json`](../../artifacts/verify-local-final.json), SHA-256 `24782affa97c0563a3ec923316a99beb3eb960a263fd763be833f0ae4b6ffec6`. Véase [verification.md](../verification.md).

## Convenciones

- API de negocio bajo `/v1`; `/healthz` queda fuera.
- JSON UTF-8 y fechas ISO 8601; la UI formatea en zona IANA del tenant.
- Sesión y MFA en cookies `HttpOnly`; CSRF double-submit para mutaciones.
- `Secure` se activa por configuración y es obligatorio detrás de HTTPS productivo.
- Tenant derivado de sesión/membresía; IDs/query/header/body/cookies nunca autorizan por sí solos.
- `Idempotency-Key` UUID en mutaciones críticas.
- `expectedVersion` para concurrencia optimista; la base añade locks/restricciones.
- Cursor opaco en listados aplicables.
- Errores con código estable y `meta.requestId`; el cliente localiza el código, no muestra mensajes internos.
- No se serializa una entidad DB completa por conveniencia.

Ejemplo:

```json
{
  "error": {
    "code": "VERSION_CONFLICT",
    "message": "The resource version changed"
  },
  "meta": {
    "requestId": "opaque-request-id"
  }
}
```

El texto `message` no es un contrato de UI y puede permanecer en inglés; no debe contener SQL, rutas, secretos ni detalles internos.

## Superficie implementada

| Tag OpenAPI | Operaciones | Alcance |
|---|---:|---|
| Access | 7 | permisos, roles locales y bindings |
| Assignments | 9 | provisional, consentimiento, presentación, decisión, finalización, vigencia, sustitución e historial |
| Audit | 1 | lectura autorizada |
| Authentication | 32 | login, passkeys/WebAuthn, MFA/enrollment, políticas, sesiones, recuperación, bootstrap, memberships y switch tenant |
| Catalog | 8 | catálogo base/local y settings tenant |
| Committee | 1 | directorio de comité |
| Custody | 11 | llaves, freeze, recipients, manifest, atestaciones y publicación |
| Dashboard | 1 | métricas autorizadas |
| Devices | 1 | solicitud de rotación |
| Events | 1 | SSE |
| Health | 1 | salud API/worker |
| Invitations | 5 | alta, lista, revocación, aceptación y recuperación del contexto de enrolamiento |
| Key Lifecycle | 9 | challenges, devices, grants, rotación, recuperación y pérdida |
| Members | 17 | padrón, contacto separado, administración, archivo/reactivación, importación, fotos y cualificaciones append-only |
| Organization | 1 | organigrama |
| Platform | 16 | tenants, aprovisionamiento, invitación inicial, recuperación gobernada, suspensión/reactivación y ciclo de exportación cifrada |
| Reports | 8 | solicitudes, artifact lifecycle, impresión, snapshot y corrección inmutable |
| Rounds | 5 | ronda activa, envío/recibo propio, participación y cierre genérico |
| Workflow | 36 | ciclos, sesiones/agenda/asistencia cifrada, vacantes, aplicabilidad, propuestas, revisión, boleta y desempate |

La suma es 165. `openapi.json` es la referencia exacta para paths, cuerpos, respuestas, permisos y códigos; esta tabla evita duplicar 165 firmas que quedarían obsoletas.

## Autorización

La API combina:

1. sesión válida y no revocada;
2. membresía activa para el tenant;
3. permiso atómico;
4. visibilidad/propiedad del objeto;
5. fase y versión;
6. CSRF, step-up o idempotencia cuando aplica.

Una pantalla oculta no autoriza. Rutas de lectura también aplican scopes para evitar IDOR: por ejemplo, reportes se filtran por par exacto `type:audience`, objetos foráneos producen 404 neutral y participación nominal exige permiso dedicado.

## Idempotencia y concurrencia

El registro conserva operación, actor, tenant, key, hash canónico y respuesta. Misma key+cuerpo reproduce el resultado; misma key+cuerpo distinto falla. Restricciones adicionales permiten una sola respuesta efectiva por elector/ronda.

Las pruebas live cubren:

- same-key retries y dos pestañas;
- envío final vs cierre;
- doble cierre con resultado único;
- tokens de invitación de un uso;
- altas/rotaciones de claves;
- solicitudes/completado/fallo de reportes.

El recibo se devuelve solo después del commit.

## SSE

`GET /v1/events` es autenticado y acepta `Last-Event-ID` o `?after=`. Publica frames con secuencia y heartbeats. Los eventos de ronda autorizados incluyen:

- `round.participation`: señal para refrescar participación;
- `round.phase`: ronda, fase y versión;
- `round.closed`: ronda, transición, versión y hora.

No incluyen candidato, selección ni relación elector–preferencia. Las pruebas cubren anclaje al final autorizado, reanudación sin duplicar, origen, tenant/cursor, límites de streams y cierre del servidor.

La API local consulta outbox; no existe broker ni garantía multiinstancia detrás de load balancer.

## Importación y fotos

Importación siempre usa preview → commit. Preview valida archivo/filas cifradas, AAD/hash/key vigente y construye decisiones explícitas; commit acepta solo el `importId`, versión y permisos requeridos. Reintentos son idempotentes.

Fotos se decodifican/recrean en cliente y se almacenan como sobre cifrado con metadatos seguros; nombres originales/EXIF/bytes claros no entran a DB/eventos. Rutas de archivo son reversibles a nivel de estado, no borrado histórico.

No hay almacén de objetos externo. Si se introduce, debe conservar autenticación, aislamiento, expiración y backup por tenant.

## Workflow y custodia

La API implementa:

- ciclos, electorate/comité, sesiones, agenda/asistencia/decisiones;
- vacancy processes y `PUT /v1/office-processes/{processId}/applicability`, con versiones de ciclo/proceso, razón cerrada, idempotencia y preservación histórica;
- enrutamiento por mecanismo: propuestas/papeletas solo para elecciones ordinarias y `COUNCIL_BOARD_PROCEDURE_REQUIRED` para procedimientos separados que necesitan una vía institucional validada;
- proposal rounds, manifest/consolidación;
- revisión versionada y candidate list;
- ballot/tiebreak rounds;
- asignaciones y transiciones institucionales;
- freeze de dos custodios, manifest de boletas, dos atestaciones coincidentes, disputa y publicación.

El servidor almacena HPKE/ciphertext/material público, no claves privadas ni selección clara.

## Reportes

El backend implementa los trece tipos, proyección por tipo/audiencia, request `pending`, complete/fail, lectura de artefacto cifrado e impresión auditada. El navegador y el escenario dedicado real-stack comparten el generador puro PDF/XLSX/CSV; el wiring, la ejecución mutable autorizada 3/3 contra API/PostgreSQL efímeros reales y el pase integral posterior están verdes. Véase [reports.md](../reports.md).

No existe endpoint que devuelva un PDF/XLSX/CSV claro persistido en servidor.

## Verificación y límites

Las pruebas OpenAPI validan estructura/paridad, pero faltan:

- un segundo validador semántico independiente;
- generación/compilación de cliente externo;
- contract testing consumer-driven;
- compatibilidad/versionado publicado;
- pruebas de proxy/TLS/multiinstancia;
- evaluación DAST/pentest.

Proveedores productivos de identidad, correo, objetos, KMS y observabilidad no están conectados. Esas ausencias se documentan en [known-limitations.md](../known-limitations.md), no como endpoints ficticios.
