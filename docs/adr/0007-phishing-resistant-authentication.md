# ADR-0007 — Passkeys, niveles de garantía y recuperación restringida

- Estado: Aceptada para la implementación local; validación de despliegue externo pendiente
- Fecha: 2026-09-13

## Contexto

El TOTP existente aporta un segundo factor real, pero sigue siendo susceptible a phishing y su enrolamiento resulta frágil cuando la persona usa la aplicación y el autenticador en el mismo teléfono. Además, una sesión recuperada mediante un código offline no debe adquirir de inmediato los mismos privilegios que una sesión autenticada con un factor resistente a phishing.

La aplicación necesita una sola arquitectura que funcione en iOS, Android, Windows y macOS, tanto en dispositivos personales como administrados, sin obligar a escanear un QR en el mismo dispositivo. También necesita distinguir el método usado, el nivel de garantía y la autorización de una operación sensible.

## Decisión

1. Las passkeys WebAuthn son el método primario. Se solicitan credenciales descubribles con verificación de usuario obligatoria. En el mismo teléfono o computador, la ceremonia usa la biometría o PIN del sistema; el QR aparece únicamente cuando el navegador ofrece autenticación entre dispositivos.
2. La API usa `@simplewebauthn/server` 14.0.1 y el cliente usa `@simplewebauthn/browser` 14.0.0. No se implementan manualmente CBOR, COSE, validación de firmas ni attestation.
3. Cada challenge se genera criptográficamente, se conserva solo como SHA-256, caduca pronto, está ligado al tipo de ceremonia, RP ID, origen, identidad o sesión cuando corresponda y se consume de forma atómica una sola vez.
4. El servidor valida challenge, origen exacto, RP ID, tipo, firma, presencia y verificación de usuario. Conserva el ID de credencial, clave pública COSE, contador, AAGUID, transports, tipo de dispositivo, estado de respaldo y fechas; nunca recibe ni almacena biometría.
5. Las sesiones expresan método, AAL, resistencia a phishing, credencial y estado de recuperación. Las operaciones de una sesión `recovery_limited` no reciben permisos del tenant ni claves de contenido: solo pueden cerrar sesión y registrar un factor de reemplazo permitido.
6. El step-up WebAuthn emite una autorización opaca, breve y de un solo uso ligada a sesión, propósito y hash canónico de la operación. La base conserva únicamente el hash del token.
7. TOTP queda como fallback AAL2. El mismo teléfono puede abrir la URI `otpauth:` mediante un gesto explícito. En PC, el QR se genera localmente; la semilla y la URI no se envían a terceros, logs, analytics ni almacenamiento persistente.
8. La IP y el user-agent se consideran señales de riesgo sanitizadas, no una identidad humana. Un cambio de red móvil no debe invalidar por sí solo una sesión legítima. El token aleatorio, la expiración, la revocación y el control de inactividad siguen siendo obligatorios.
9. La política global define un piso y la política por tenant solo puede endurecerlo. Los roles privilegiados deben migrar a autenticación resistente a phishing y mantener más de un autenticador antes de activar enforcement estricto.

## Límites de garantía

- Una passkey sincronizable con verificación de usuario puede formar parte de una implementación AAL2, pero no prueba por sí sola la conformidad completa del ciclo de identidad.
- AAL3 requiere autenticadores no exportables protegidos por hardware, attestation y políticas operacionales verificadas. No se declara AAL3 por software local.
- El RP ID y los orígenes HTTPS definitivos deben decidirse antes del enrolamiento productivo; cambiarlos invalida la relación de las credenciales existentes.
- La federación OIDC/SAML, SCIM, KMS/HSM, FIDO Metadata Service, SIEM/WORM, dispositivos administrados y notificaciones independientes requieren proveedores y configuración del entorno de producción. Los adaptadores locales no sustituyen esas validaciones.
- La certificación de producción requiere pruebas físicas en navegadores y dispositivos objetivo, revisión independiente de seguridad y ejercicios de recuperación.

## Consecuencias

- El acceso cotidiano mejora: passkey-first y autofill reducen contraseña y TOTP, pero siempre existe una salida clara hacia métodos alternativos.
- La recuperación ya no es una vía para ejecutar operaciones privilegiadas.
- Revocar una passkey o sesión es inmediato para nuevas solicitudes, aunque no puede borrar información que un dispositivo autorizado ya haya visto.
- Las cuentas privilegiadas necesitan una transición administrada para evitar bloquear a quienes todavía solo tienen TOTP.
- La evidencia local demuestra comportamiento técnico en el entorno documentado; no se presenta como certificación Fortune 500, NIST, FIDO u OWASP emitida por terceros.

## Referencias

- NIST SP 800-63B-4, Authentication and Authenticator Management.
- W3C Web Authentication Level 3.
- OWASP Authentication y Multifactor Authentication Cheat Sheets.
- FIDO Alliance, passkey UX y despliegue empresarial.
