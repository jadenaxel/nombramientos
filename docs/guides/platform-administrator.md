# Guía del administrador global

Esta guía describe la operación del plano global. El rol global administra disponibilidad y ciclo de vida de tenants, pero no puede leer padrones, deliberaciones, votos, reportes cifrados ni claves E2EE de una iglesia.

## Acceso seguro

1. Abra `/{idioma}/auth/sign-in` y autentíquese con su identidad nominal.
2. Complete MFA. El bootstrap inicial sólo crea una sesión de inscripción; no habilita operaciones antes de confirmar el segundo factor.
3. Entre a `/{idioma}/app/platform`. La web bloquea el vault tenant y purga las consultas locales antes de mostrar el plano global.
4. No copie tokens, códigos de recuperación, URI TOTP o secretos a tickets, chats o capturas.

## Aprovisionar y activar una iglesia

1. En **Plataforma**, compruebe que el worker está saludable.
2. Registre nombre, slug, zona IANA e idioma. La solicitud queda en cola; el navegador no recibe credenciales de base de datos.
3. Espere el estado **Activación pendiente**. Una iglesia real no se activa por el mero hecho de crear su base.
4. Genere la invitación de primer administrador. El token se muestra una sola vez y debe entregarse por un canal independiente.
5. Confirme que la aceptación y el MFA del administrador cambian el tenant a activo. Nunca cargue fixtures de Demo en un tenant real.

## Operación y ciclo de vida

- **Salud:** revise API, worker, cola y último error sanitizado; use el ID de correlación para investigar.
- **Suspensión:** exige MFA reciente y un código de razón cerrado. Revoca sesiones; no borra datos.
- **Reactivación:** exige permiso separado, MFA reciente y un nuevo inicio de sesión de los usuarios.
- **Exportación:** obtenga autorización de un uso, ejecute el worker y descargue sólo el ciphertext con su manifiesto.
- **Baja:** prográmela únicamente después de una exportación válida y del plazo de retención. La ejecución local no purga físicamente sin autoridad de retención explícita.

## Respuesta a incidentes

No suplante usuarios ni emita propuestas o votos. Suspenda el tenant cuando corresponda, preserve los IDs de correlación y siga [Operación y continuidad](../operations.md). La recuperación administrativa no recupera automáticamente claves E2EE.

