# Privacidad

## Estado y responsabilidad

Los datos pueden revelar afiliación religiosa y decisiones internas. Cada iglesia debe identificar formalmente al responsable del tratamiento, finalidades, base aplicable, jurisdicción y contactos. Este documento es un diseño de privacidad, no asesoría ni dictamen legal.

La asociación/misión, unión, división, país de residencia de datos y legislación aplicable a Ozama están **pendientes de confirmación y asesoría competente**.

## Minimización

| Categoría | Mínimo previsto | No recopilar por defecto |
|---|---|---|
| Cuenta | identificador, destinatario de invitación, MFA, sesiones | contactos no necesarios |
| Padrón | ID estable, identidad visible separada, membresía, elegibilidad y disponibilidad | fecha de nacimiento, domicilio, teléfono o correo de todas las personas |
| Contacto opcional | sobre separado únicamente cuando exista finalidad y permiso explícitos | combinar correo/teléfono con la identidad visible o exigirlos para votar |
| Foto | imagen opcional autorizada y miniaturas | EXIF, geolocalización, reconocimiento facial |
| Elegibilidad | estado, vigencia, responsable y motivo mínimo autorizado | expedientes disciplinarios, médicos o financieros |
| Cualificación | tipo, estado explícito, fechas civiles, versión y revisor; título/emisor opcionales dentro de un sobre E2EE separado | narrativas, expedientes de respaldo o uso automático como señal de elegibilidad |
| Nota restringida | mínimo administrativo imprescindible | narrativas extensas o datos ajenos |
| Participación | recibo nominal/estado | preferencia ligada al elector |
| Boleta/propuesta | contenido E2EE | texto en claro en backend/logs |
| Auditoría | actor seudónimo cuando proceda, acción, entidad, hora, resultado | cuerpo de boleta, claves, notas y tokens |

## Finalidades

- Preparar y documentar ciclos de nombramientos autorizados.
- Gestionar elegibilidad, vacantes y consentimiento.
- Documentar formación, ordenación y otras cualificaciones sin inferir idoneidad ni alterar elegibilidad o resultados electorales.
- Recibir propuestas y votos internos de la junta.
- Generar recomendaciones, actas, reportes y organigramas autorizados.
- Mantener seguridad, auditoría, continuidad y soporte limitado.

No usar los datos para publicidad, venta, perfilado comercial, clasificación de espiritualidad, reconocimiento facial, entrenamiento de IA o analítica que capture formularios.

## Audiencias y destinatarios

| Contenido | Audiencia máxima por defecto |
|---|---|
| Identidad visible del padrón | administradores y junta autorizada |
| Contacto opcional | permiso independiente `member.contact.read` |
| Motivo visible | junta autorizada |
| Cualificaciones | permiso independiente `member.qualification.read`; título/emisor solo tras descifrado cliente autorizado |
| Nota restringida | permiso específico |
| Participación nominal | conductor autorizado, sin preferencias |
| Preferencias | custodios durante escrutinio autorizado |
| Agregados internos | junta según configuración |
| Informe congregacional | iglesia; versión mínima deliberadamente publicada |
| Salud operativa | administrador global sin contenido del tenant |

Correo solo contiene información mínima y enlaces autenticados; nunca votos o deliberaciones. La demo no envía a direcciones reales.

## Cualificaciones independientes

El registro de cualificaciones es append-only y separado del estado de elegibilidad. Formación, ordenación, certificación u otra condición documentada nunca concede, revoca ni presume elegibilidad, disponibilidad, candidatura, asignación o resultado electoral. Crear o revisar requiere `member.qualification.manage`, MFA reciente, CSRF, idempotencia y versión esperada; leer requiere `member.qualification.read`.

El backend necesita observar únicamente los metadatos estructurados del registro —tipo, estado explícito, fechas civiles, versión y revisor— para validar y ordenar historia. El título y el emisor son opcionales y permanecen dentro de un sobre E2EE con AAD exacto. Cada revisión se abre con la clave señalada por su propio `envelope.keyId`; si el dispositivo no conserva el grant histórico `retired` correspondiente o el plaintext no cumple el esquema cerrado, la UI muestra los detalles como no disponibles y no usa un fallback inseguro.

En los eventos de cambio, metadata de audit y payload de outbox no duplican miembro, tipo, estado, fechas, indicador de presencia de detalles, título, emisor ni ciphertext. Conservan solo identificador opaco, versión y `eligibilityInference: false`; la auditoría de lectura conserva el miembro consultado como referencia mínima de la entidad. Esta minimización reduce exposición secundaria, pero no convierte en anónimos los metadatos que un principal autorizado consulta en el endpoint.

## Retención propuesta para validación

Estas duraciones son marcadores de política, no reglas legales aprobadas:

| Categoría | Propuesta inicial | Acción al vencer |
|---|---|---|
| Invitación | hasta uso o 72 horas | invalidar y conservar evento mínimo |
| Sesión | duración configurada corta; máxima a validar | revocar/eliminar token |
| Borrador local | sesión o plazo breve cifrado | eliminar al cerrar sesión/cambiar tenant |
| Fotos originales | mientras exista finalidad/consentimiento | eliminar original y miniaturas según política |
| Boletas/propuestas | plazo aprobado después de cierre/impugnación | destrucción criptográfica o retención cifrada |
| Reportes temporales | 24–72 horas para descarga | eliminar artefacto; conservar versión/evidencia mínima |
| Actas/resultados históricos | política eclesiástica/legal aplicable | archivar con acceso mínimo |
| Auditoría de seguridad | plazo proporcional al riesgo y ley | eliminación o anonimización cuando proceda |
| Backups | ventana de restauración aprobada | expiración verificable por tenant |

## Derechos y rectificación

El tenant debe publicar contacto y procedimiento para acceso, corrección, objeción o eliminación conforme a la ley aplicable. Los documentos históricos y registros append-only se corrigen mediante una entrada/versionado nuevo, sin ocultar indebidamente la historia. Debe equilibrarse la conservación institucional con minimización y derechos.

## Fotos

- Definir autorización/consentimiento aplicable.
- Opción real de no aportar foto.
- Validar bytes, recrear imagen y eliminar metadatos.
- No inferir identidad, edad, género, etnia, salud o idoneidad desde la foto.
- Aislar originales/miniaturas por tenant.

## Proveedores

Antes de producción registrar para identidad, correo, hosting, almacenamiento, backups, observabilidad y soporte:

- entidad legal y ubicación;
- datos recibidos;
- finalidad y base;
- subencargados;
- retención y eliminación;
- controles y notificación de incidentes;
- transferencias internacionales;
- contrato aplicable.

No hay proveedores de producción aprobados en esta entrega.
