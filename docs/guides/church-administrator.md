# Guía del administrador de iglesia

El administrador de iglesia configura su propio tenant. No recibe poderes globales, derecho de voto automático ni claves privadas por tener el rol `CHURCH_ADMIN`.

## Primer ingreso

1. Abra la invitación y escriba manualmente el token recibido por el canal seguro; el token no se admite en la URL.
2. Defina una contraseña individual y complete MFA antes de usar privilegios.
3. Registre el dispositivo E2EE y verifique su huella por un canal humano independiente. Guarde la copia cifrada fuera del navegador.
4. Revise `/{idioma}/app/settings`: nombre, zona, idioma y estado de configuración pertenecen al tenant autenticado.

## Preparación

1. En **Acceso**, asigne sólo los permisos delegables necesarios. Los roles `LOCAL_*` no pueden incluir `platform.*` ni superar al actor.
2. En **Miembros**, importe CSV/XLSX mediante vista previa; resuelva crear/actualizar/omitir antes de confirmar. Contacto, nombre visible, foto, elegibilidad y nota privada usan límites de acceso distintos.
3. En **Catálogo**, revise fichas canónicas y cree extensiones locales sin reescribir la fuente normativa.
4. En **Comité**, registre integrantes y funciones. Ser integrante no basta para votar: cada ronda congela su padrón.
5. En **Flujo**, cree el ciclo, vacantes y procesos; compruebe zona horaria, cardinalidad y reglas antes de abrir.

## Conducción y resultados

- Abra una sola etapa a la vez y confirme cargo, límite y padrón congelado.
- Use el panel de participación para seguimiento; no intente inferir preferencias.
- Revise candidaturas con códigos de decisión cerrados. Las notas privadas nunca deben copiarse al padrón o reporte ordinario.
- Publique agregados sólo tras atestaciones compatibles de custodios. Una discrepancia o clave ausente bloquea la publicación.
- Registre consentimiento, recomendación, presentación y elección congregacional como estados distintos.
- Emita reportes con audiencia, filtros e idioma correctos; los artefactos listos se verifican contra su manifiesto antes de abrirse.

## Cierre diario

Revise pendientes, exporte únicamente con autorización MFA, cierre sesión y conserve copias/recibos según [Operación y continuidad](../operations.md). No use reset de Demo sobre una iglesia real.

