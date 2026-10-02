# ADR-0008 — Sesión de Nombramientos vinculada al navegador autorizado

- Estado: decisión autorizada e implementación aplicada; API/criptografía verificadas localmente y recorrido integrado de navegador aprobado4/4. No es aprobación productiva ni certificación independiente.
- Fecha: 2 de octubre de 2026.
- Alcance: corrección D10, con GestionChurch como proveedor de identidad. No habilita MFA ni autoriza modificar cargos, claves privadas, contenido cifrado o custodia de iglesias reales.

## Problema y objetivo

La sesión anterior identifica a una persona. El guard de escritura permite operar mientras esa persona tenga cualquier dispositivo/grant vigente. Revocar el dispositivo B no impide que su cookie opere si A sigue autorizado. Vincular un `deviceId` declarado por el cliente no corrige esa brecha.

Conservar el control por dispositivo, pero hacer que las verificaciones rutinarias ocurran en segundo plano. Un navegador nuevo pasa por un paso guiado y una aprobación o recuperación explícita, sin otorgar autoridad por el mero hecho de ser administrador. Un navegador reconocido no requiere registrar otra computadora en cada ingreso.

## Decisión de seguridad

1. Cada navegador usa una clave de firma ECDSA P-256/ES256 distinta de su clave HPKE de cifrado. La clave privada de firma se conserva como `CryptoKey` no extraíble en IndexedDB; no se exporta a JWK/PKCS#8, no se envía al servidor ni se guarda en `localStorage`/`sessionStorage`. Esto no acredita protección hardware ni elimina el riesgo de XSS o de un sistema operativo comprometido.
2. Asociar una clave de firma a un dispositivo existente exige demostrar control de la clave privada de cifrado ya registrada: el servidor sella un desafío aleatorio HPKE para esa clave pública, con propósito separado del cifrado de contenido. La respuesta demuestra descifrado y posesión de la nueva clave de firma. Contexto y expiración ligan iglesia, identidad, sesión original de GestionChurch, sesión del módulo, dispositivo y huellas. La cookie y una firma con una clave elegida por el atacante no bastan para apropiarse de un dispositivo existente.
3. La asociación de firma es inmutable. Perder una clave privada no autoriza sobrescribir una clave registrada ni reabrir un dispositivo revocado. El reemplazo se realiza desde otro navegador o un perfil nuevo, sin borrar las claves antiguas, con alta/aprobación o recuperación offline explícita; la guía actual no sustituye el dispositivo dentro del mismo perfil que conserva sus registros. Nunca obtiene permisos, historia ni claves por deducción de su rol.
4. Cada solicitud protegida presenta una prueba firmada ES256 de un uso. El perfil utiliza las ideas de JWS/DPoP para método, URI, identificador y nonce, y añade contexto exacto de sesión/tenant/dispositivo, ruta con query, hash del cuerpo e idempotencia. El nonce lo emite el servidor, caduca pronto y su consumo se serializa en PostgreSQL. No se transportan pruebas en la URL.
5. Este es un perfil de aplicación para cookies, **no una implementación OAuth DPoP certificada ni una afirmación de conformidad completa con RFC 9449**. DPoP por sí solo no firma el cuerpo. La integridad adicional del cuerpo/query/idempotencia debe tener pruebas negativas independientes y documentación de su serialización exacta.
6. La autenticación, autorización central y permisos del tenant siguen siendo obligatorios. Posesión de una clave no confiere derecho a votar, custodiar un escrutinio o administrar. CSRF, cookies HttpOnly/SameSite/Secure, expiración absoluta/inactividad, límites de tráfico y origen permitido se conservan. Producción exige HTTPS y origen público configurado; no se deriva confianza de `Host`/cabeceras de proxy arbitrarias.
7. El guard transaccional fija la sesión vinculada y el dispositivo/grant/generación exactos antes de escribir. Revocar el dispositivo invalida sus vínculos en la base del tenant en la misma transacción. La eliminación de acceso no depende exclusivamente de una segunda operación en el control plane. Las sesiones afectadas se revocan también en control; otros dispositivos de la misma persona siguen independientes.
8. Se mantienen únicamente excepciones de bootstrap/recuperación necesarias y acotadas. Consultar la sesión, cerrar sesión, ver el estado del alta o registrar un dispositivo pendiente no permite acceder al contenido protegido, aprobar grants por una sesión no demostrada o cambiar claves existentes. Las sesiones antiguas deben completar la verificación, no convertirse silenciosamente en sesiones confiables.
9. Las conexiones en vivo presentan prueba al abrir y revalidan fuente central, sesión y dispositivo durante su vida. No se deja una conexión previamente abierta como vía residual después de una revocación.
10. El usuario conserva una lista de sesiones activas, última actividad y cierre de una o de las demás sesiones, con confirmación, estados reales y auditoría sin material secreto. El cierre local bloquea el vault correspondiente; no promete borrar información ya vista o copiada.
11. La lectura autenticada de sesión publica su identificador exacto y la hora del servidor, sin extender la expiración absoluta. La política existente de inactividad se conserva. La preparación del navegador comparte un estado ligado a esa sesión, identidad, tenant, fuente y firmante: ninguna consulta protegida se adelanta a esa verificación. Navegar entre pantallas conserva el contexto de la misma sesión; cierre, expiración y cambio de identidad/iglesia siguen limpiándolo explícitamente.
12. Las verificaciones centrales no se cachean para ocultar un límite de tráfico. El gateway utiliza un presupuesto acotado separado sólo para las tres operaciones internas exactas con secreto autenticado, conservando los límites públicos y reservando apertura de sesiones ante introspecciones sobrecupo. Esto no confiere autoridad ni reemplaza las comprobaciones de origen, rol, dispositivo o revocación. El diagnóstico de rechazos guarda sólo operación enumerada, estado HTTP y hora; nunca código de lanzamiento, URL privada, cabeceras o cuerpo. La configuración y límites operativos se documentan en el runbook de GestionChurch; la capacidad y cuota HA durante una caída de Redis requieren ensayos productivos independientes.

## Preservación y recuperación

La migración es aditiva. No transforma ciphertext, grants HPKE, claves de recuperación, períodos, votos, cargos ni generaciones históricas. Una sesión antigua se verifica con su material existente o usa la recuperación explícita. Un fallo temporal debe dar una salida clara para reintentar o volver a GestionChurch, sin simular aprobación ni regenerar claves.

Revocar no borra claves o información extraída antes de la revocación. Ante compromiso, la rotación sigue siendo una acción separada y explícita. Ningún rol global permite descifrar datos de otro tenant. El acceso histórico sigue ligado al `keyId` exacto y a concesiones autorizadas; nunca se sustituye una clave histórica por la actual.

## Validación obligatoria del nuevo corte

- A funciona y B revocado no puede leer/escribir ni administrar claves usando su cookie anterior, aunque ambos pertenezcan a la misma persona.
- Copiar una cookie sin la clave privada, declararse como otro dispositivo o reemplazar su firmante falla.
- Firma inválida, replay, nonce vencido, cambios de método/ruta/query/cuerpo/idempotencia/tenant/identidad/sesión/fuente fallan.
- Una revocación concurrente con escritura se serializa; no existe autorización por snapshot obsoleto.
- Bootstrap/alta pendiente no crea grants implícitos; los permisos centrales de comisión/custodia siguen explícitos.
- Recuperación/rotación y lectura histórica preservan el mismo contenido; rollback y respuesta perdida no crean asociaciones incompatibles.
- Flujo guiado, sesiones y alertas funcionan en ES/EN/FR, móvil y escritorio, sin rutas locales de MFA habilitadas en modo integrado.
- Los ensayos usan únicamente bases, identidades y archivos sintéticos propios, con prueba de propiedad y cleanup; no se modifica Central/Ozama durante QA.

La evidencia se publica separada de los resultados anteriores en [el informe D10 de GestionChurch](X:/CODE/GestionChurch/docs/premium-device-sessions-2026-10-02.md). El piloto humano, dispositivos físicos y la revisión criptográfica/pentest independiente siguen pendientes; no se declaran certificaciones NIST, FIDO, OWASP o WCAG.

## Referencias primarias

- [RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449.html), especialmente §4 y §11.7 (integridad del cuerpo no incluida).
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html).
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html), propósito y contexto de aplicaciones.
- [OWASP: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), invalidación en servidor y gestión de sesiones.
- [NIST SP 800-63B-4: sesiones](https://pages.nist.gov/800-63-4/sp800-63b.html#session-management), pruebas de posesión y límites de garantía.
