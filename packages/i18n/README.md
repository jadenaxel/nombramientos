# @nombramientos/i18n

Mensajes base ES/EN/FR para navegación, flujos críticos, estados, errores, accesibilidad y documentos.

- Español es el locale inicial propuesto para Ozama.
- Las claves son estables y no deben construirse desde texto visible.
- Los objetos EN y FR se validan en TypeScript contra todas las claves ES.
- Se usa sintaxis ICU para variables y plurales; la aplicación debe renderizarla con una biblioteca mantenida como `next-intl`.
- El glosario es una traducción de trabajo pendiente de revisión eclesiástica. No constituye una traducción oficial de los manuales.
- Nombres propios, identificadores y recibos opacos nunca se traducen.
- La zona horaria pertenece al tenant; el idioma pertenece al usuario.
