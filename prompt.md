# Prompt maestro — Plataforma de nombramientos de iglesias adventistas

**Idioma del encargo:** español. **Fecha de preparación y consulta inicial:** 10 de septiembre de 2026.  
**Nombre de trabajo:** Nombramientos Adventistas; editable y sujeto a revisión de identidad institucional.  
**Destino inicial:** Iglesia Adventista Ozama y un tenant independiente de demostración.  
**Uso:** entregar este documento completo al equipo o agente que implementará el producto. Este archivo especifica la aplicación; su existencia no significa que la aplicación esté construida, certificada o desplegada.

## 1. Misión y forma de trabajar

Actúa como un equipo integrado de arquitectura de software, desarrollo full stack sénior, diseño UX/UI, accesibilidad, ingeniería de seguridad, privacidad, pruebas y operaciones. Diseña, implementa, prueba y documenta una aplicación web real para las juntas o comisiones de nombramientos de la Iglesia Adventista del Séptimo Día.

Entrega una experiencia institucional excepcional: elegante, clara, rápida y especialmente cómoda en celulares. La calidad debe demostrarse mediante flujos completos, datos persistentes, diseño coherente y pruebas reproducibles. No sustituyas funciones por pantallas estáticas, botones sin acción, contadores inventados o simulaciones conectadas solamente a memoria del navegador.

La plataforma será gratuita para sus usuarios y de uso exclusivo de iglesias adventistas. No incluirá cobros, publicidad ni monetización de datos. Distingue la gratuidad del servicio de los costos reales de infraestructura, almacenamiento, correo, copias de seguridad y mantenimiento; documenta una operación económica y una opción de instalación propia.

Implementa en JavaScript moderno con TypeScript estricto, tanto en frontend como backend. Python es admisible para herramientas auxiliares si aporta una ventaja concreta. Utiliza componentes estables, mantenidos y con licencias compatibles, verificando sus versiones y avisos de seguridad al comenzar. No uses versiones experimentales ni dependencias flotantes en producción.

Trabaja por entregas funcionales, conservando el alcance completo. Resuelve decisiones reversibles con criterio profesional. Registra supuestos y decisiones de arquitectura. Solicita solamente los datos externos imprescindibles que no puedan obtenerse de fuentes o configuración, y continúa las partes independientes. Nunca inventes credenciales, avales eclesiásticos, políticas, traducciones oficiales, resultados de pruebas o certificaciones.

## 2. Autoridad eclesiástica y fuentes verificables

### 2.1 Base documental

La referencia inicial verificada es el **Seventh-day Adventist Church Manual, 21.ª edición, revisada en 2025**. Una comunicación oficial confirma que incorpora las modificaciones de la sesión de 2025. Revalida su vigencia al implementar; no deduzcas la edición por un resultado de búsqueda o por los metadatos del PDF. [Confirmación oficial de la edición](https://stewardship.adventist.org/the-church-manual-and-its-relevance-to-the-local-church).

Utiliza el [portal oficial del Manual de Iglesia](https://gc.adventist.org/church-manual/) y el [PDF oficial revisado en 2025](https://gc.adventist.org/wp-content/uploads/2025/10/Seventh-day_Adventist_Church_Manual-2025-10-13.pdf). La referencia operativa inicial comprende los capítulos sobre dirigentes y elecciones y las notas relacionadas. Verifica siempre la paginación impresa y la posición dentro del PDF.

El [Manual del Anciano, revisión 2016, publicado por la Asociación Ministerial](https://cdn.ministerialassociation.org/docs/ebooks/Seventh-day%20Adventist%20Elder%27s%20Handbook%20%28rev.2016%29.pdf) es una edición oficial verificable de apoyo. No la denomines «última edición mundial» sin nueva comprobación. Sus referencias a ediciones anteriores no deben reemplazar las reglas vigentes del Manual de Iglesia.

Las traducciones y suplementos regionales deben corresponder a la jurisdicción de cada tenant. Confirma con la iglesia la asociación/misión, unión y división aplicables a Ozama antes de adoptar políticas regionales. No apliques automáticamente un suplemento de otra división porque esté en español. Conserva la fuente oficial original aunque la interfaz presente una traducción de trabajo claramente identificada.

### 2.2 Diferencia entre recomendación y elección

La comisión estudia candidatos y presenta recomendaciones; la elección corresponde a la iglesia. Las deliberaciones son confidenciales y se requiere consultar la disposición de las personas propuestas. El pastor no es una vacante que esta comisión deba elegir. Algunas funciones tienen otro mecanismo de designación. Estos límites deben reflejarse en el producto, no quedar solamente en documentación. [Manual de Iglesia, capítulo 10, pp. 120–124 y notas relacionadas](https://gc.adventist.org/wp-content/uploads/2025/10/Seventh-day_Adventist_Church_Manual-2025-10-13.pdf).

Por tanto, implementa estados distintos para resultado interno, recomendación, aceptación del candidato, presentación del informe y elección por la iglesia. «Más votos en la junta» no debe convertirse automáticamente en «elegido por la iglesia». Las reglas internas de pluralidad, unanimidad de participación digital y organización de pantallas son decisiones de producto configurables; no las atribuyas al manual sin respaldo.

### 2.3 Motor de reglas y trazabilidad

Crea una matriz `normative-matrix` con un registro por regla: identificador estable, texto resumido, autoridad, edición, idioma, capítulo/sección, página impresa, página PDF, URL, fecha de consulta, ámbito territorial, interpretación, requisito de producto, implementación y pruebas asociadas.

Clasifica cada entrada como `norma_manual`, `disposicion_regional_validada`, `practica_local_aprobada`, `configuracion_producto` o `pendiente_validacion`. No presentes una preferencia local como mandato universal. Documenta conflictos entre fuentes y resuélvelos según la autoridad aplicable; el Manual del Anciano y los materiales de apoyo no sustituyen el Manual de Iglesia.

Versiona el paquete normativo. Cada ciclo conserva su versión, configuración y validación local; actualizar fuentes no reescribe ciclos anteriores. Una regla normativa obligatoria no puede desactivarse mediante un permiso genérico de administrador. Los asuntos pendientes deben quedar visibles a los responsables y no recibir una etiqueta falsa de conformidad.

Incluye biblioteca contextual del Manual de Iglesia y del Manual del Anciano, con edición, índice, búsqueda y acceso a fuentes. Verifica permisos antes de redistribuir libros o traducciones completos. Si no existe autorización para alojarlos, ofrece enlaces oficiales y fichas originales con referencias. Un enlace debe identificarse como tal; no simular un documento incorporado.

Para cada cargo, ofrece una ficha breve con propósito, responsabilidades, coordinación, elegibilidad, mecanismo de nombramiento y referencias. Añade referencias bíblicas y de Elena G. de White solamente si son pertinentes y verificables. Utiliza el [sitio del Ellen G. White Estate](https://whiteestate.org/) y su [biblioteca de escritos](https://egwwritings.org/). No inventes citas ni uses una reflexión espiritual para crear una prohibición administrativa. Evita reproducir extensamente material protegido. La interfaz principal no estará cargada de textos bíblicos.

## 3. Modelo institucional y catálogo de cargos

Distingue claramente estos conceptos:

| Concepto | Significado en la aplicación |
| --- | --- |
| Tenant | Una iglesia, con base de datos propia y límites de acceso independientes. |
| Ciclo de nombramientos | Período para preparar la directiva de un mandato determinado; admite varias sesiones. |
| Mandato | Fechas efectivas del servicio de la directiva, independientes de las fechas de votación. |
| Junta de nombramientos | Grupo autorizado para participar en ese ciclo, con presidente/pastor y secretario identificados. |
| Departamento o ministerio | Unidad organizativa con sus funciones y estructura. |
| Cargo eclesiástico | Responsabilidad dentro de la iglesia; no confundir con un rol de acceso informático. |
| Vacante | Plaza concreta a cubrir para un cargo y mandato. |
| Proceso de cargo | Conjunto de propuestas, depuración, rondas, decisiones y cierre de una o más plazas relacionadas. |
| Ronda | Instancia versionada de propuestas o votación, con padrón y reglas congelados. |
| Candidato | Miembro del padrón considerado para una responsabilidad. |
| Asignación | Relación persona–vacante–mandato, con estado y procedencia verificables. |

Entrega un catálogo completo de cargos y funciones locales contemplados en la edición aplicable. Construye un inventario exhaustivo contra el manual, sus notas y las disposiciones regionales validadas; no te limites a los ejemplos de este documento. Distingue cargos elegidos, designaciones por otra autoridad, membresías por función, comisiones y estructuras opcionales. No conviertas todos los departamentos de la Asociación General en cargos obligatorios de una iglesia local.

Esta es una **lista inicial de cobertura para la implementación**, sujeta al cotejo anterior y no una transcripción normativa: ancianos y primer anciano; diáconos y diaconisas con sus coordinaciones; secretaría; tesorería y auxiliares; interesados; juntas y comisiones; Escuela Sabática, divisiones e inversión; Escuela Bíblica y escuela bíblica de vacaciones; Ministerios Personales; Dorcas/servicios comunitarios; Ministerios de la Mujer, Familia, Infantil, Salud, Mayordomía y Comunicación; educación y Hogar y Escuela; libertad religiosa; jóvenes, Embajadores y universitarios; Conquistadores; Aventureros; música; publicaciones; oración; Espíritu de Profecía; posibilidades y atención a personas con discapacidad. Incluye también todos los cargos adicionales encontrados durante el inventario oficial.

Para cada unidad, modela dirección, asociados, secretaría, tesorería e integrantes **cuando realmente correspondan**. No agregues automáticamente cinco cargos a cada departamento. Una denominación local como «Dorcas» puede funcionar como alias de una estructura reconocida; preserva la equivalencia y su alcance sin duplicar vacantes.

El catálogo debe permitir:

- Crear y editar departamentos, subunidades y cargos locales con permisos específicos.
- Mantener intacta la referencia canónica y registrar las ampliaciones como locales.
- Configurar cupos, jerarquía, dependencias, orden de trabajo, aplicabilidad y fechas.
- Seleccionar un cargo singular o varias plazas homogéneas; no mezclar cargos diferentes en una sola boleta.
- Desactivar estructuras no aplicables sin borrar historia ni falsear porcentajes.
- Representar cargos ex officio y designaciones externas sin someterlos a una elección incorrecta.
- Conservar nombres y descripciones en español, inglés y francés, con glosario institucional.
- Registrar formación, ordenación u otras condiciones aplicables por separado de la elección, sin inferirlas de un resultado electoral.

Cada ficha tendrá `canonicalCode`, nombres y alias por idioma, propósito, responsabilidades, dependencia, mecanismo de designación, cardinalidad, condiciones verificadas, referencias, alcance regional, versión y estado de revisión. Las reglas de elegibilidad se basarán en disposiciones verificadas y revisión humana; no se inferirán de fotografías, nombres, inteligencia artificial o datos financieros importados.

## 4. Multi-tenancy y configuración inicial

Implementa **database-per-tenant** real. Cada iglesia tendrá su base de datos y credencial de ejecución exclusiva, migraciones, archivos, claves, copias y registros aislados. Un esquema compartido con `tenant_id` o una política RLS por sí solos no satisfacen este requisito. Es admisible compartir inicialmente un clúster PostgreSQL si los permisos impiden que las credenciales de una iglesia se conecten a otra base.

Separa un plano de control global para registro de tenants, estado de aprovisionamiento, referencias a secretos y operación. No almacenes allí padrones, notas, votos ni informes de iglesias. La identidad global, si se usa, contendrá solamente lo mínimo para autenticación; la autorización e información de cada iglesia pertenecen al tenant.

Resuelve el tenant a partir de una sesión autenticada y una membresía validada. Un identificador recibido en URL, cabecera o cuerpo nunca será autoridad suficiente. Comprueba el alcance en HTTP, eventos en vivo, archivos, tareas en cola, exportaciones y acceso a claves. No enumeres iglesias ni membresías privadas a usuarios sin permiso.

El aprovisionamiento será idempotente y auditable: solicitud/registro de iglesia, verificación administrativa, reserva de identificador, creación de base y credenciales, migraciones, catálogo, claves y configuración, invitación del primer administrador y activación. Incluye recuperación de fallos parciales, suspensión, exportación y baja con retención definida. Las credenciales de aprovisionamiento no estarán disponibles al proceso web ordinario.

### Tenants requeridos

| Tenant | Contenido inicial obligatorio |
| --- | --- |
| Iglesia Demostración | Datos enteramente sintéticos; personas ficticias, comité, ciclos históricos, proceso actual, votos y reportes coherentes. Etiqueta persistente «Demostración». |
| Iglesia Adventista Ozama | Base propia, catálogo institucional y configuración inicial. Cero miembros ficticios, comités, ciclos, propuestas, votos, asignaciones o informes simulados. Administrador inicial mediante activación segura. |

Ozama debe abrir en un estado vacío cuidado, con pasos para completar configuración, importar padrón y constituir la junta. Si no se conoce la identidad de su administrador, provisiona una invitación pendiente mediante comando seguro; no inventes un correo ni una contraseña pública.

Crea un administrador global mediante un procedimiento de bootstrap de un solo uso, con MFA obligatorio. No incluyas secretos en Git, documentación, screenshots ni datos seed. La demo tendrá usuarios de prueba para los distintos perfiles; sus accesos de desarrollo no funcionarán en Ozama ni en producción. El reseteo de demo jamás puede recibir un tenant arbitrario.

## 5. Identidades, junta de nombramientos y permisos

Implementa permisos atómicos y roles editables dentro de límites seguros. Una persona puede pertenecer a varias iglesias únicamente mediante autorizaciones explícitas e independientes. Cambiar de tenant invalida contexto, cachés y claves del tenant anterior.

| Perfil inicial | Facultades predeterminadas |
| --- | --- |
| Administrador global | Aprovisionar y administrar operación de tenants, suspensiones, soporte y seguridad global. No obtiene automáticamente claves ni votos de iglesias. |
| Administrador de iglesia | Configurar tenant, padrón, usuarios, roles locales, ciclos y reportes permitidos. |
| Presidente/coordinador de junta | Dirigir sesiones, revisar configuración y ejecutar transiciones autorizadas. Registrar si es pastor y su condición dentro del comité. |
| Secretario de junta | Preparar ciclos, agenda, vacantes, asistencia, seguimiento, depuración, cierres, actas y reportes según delegación. |
| Miembro de junta | Consultar el proceso activo y fichas, proponer, votar y ver participación y resultados agregados autorizados. |
| Custodio de escrutinio | Gestionar la operación de claves y recuento que le haya sido delegada; no equivale a administrador general. |
| Auditor/consulta | Consultar historial y evidencias permitidas sin cambiar decisiones ni acceder a preferencias individuales. |

Admin o secretario no reciben derecho de voto automáticamente: deben figurar en el padrón de electores de la ronda. Distingue presencia, asesoría y derecho a voto para pastor, invitados y otros asistentes conforme a la configuración eclesiástica validada.

Permisos mínimos: gestionar miembros/elegibilidad/fotos, importar, gestionar comité, configurar cargos y vacantes, abrir/cerrar propuestas, ver participación nominal, depurar, abrir/cerrar votación, custodiar/recontar, publicar agregados, registrar aceptación y elección congregacional, exportar cada clase de informe, ver notas restringidas, leer auditoría, gestionar roles y activar recuperación.

Aplica denegación predeterminada y mínimo privilegio. Un rol local nunca puede otorgar poderes globales, acceder a otro tenant, revelar votos individuales o desactivar controles obligatorios. La delegación no puede conceder más privilegios que los delegables del actor. Versiona cambios y revoca sesiones cuando corresponda.

La interfaz mostrará únicamente opciones pertinentes al rol, pero la API validará todos los permisos independientemente de lo visible. Evita impersonación silenciosa. Cualquier acceso de soporte al contenido requiere una concesión explícita, limitada, revocable y auditada; no debe permitir acceso retroactivo a boletas secretas.

Registra por ciclo: miembros de junta, identificador de persona y usuario, función, presidente/pastor, secretario, fechas de incorporación/retiro, derecho a voto, sesiones asistidas y suplencias. La desactivación de una cuenta no elimina su participación histórica.

## 6. Padrón de miembros, fotografías y elegibilidad

Usa un identificador estable por persona. Conserva nombres originales con tildes y apellidos completos; una coincidencia de nombre no identifica por sí sola al mismo miembro. Permite homónimos y combina fotografía opcional con un identificador interno corto y datos mínimos autorizados.

Incluye alta/edición/archivo, pertenencia a la iglesia, estado de elegibilidad, disponibilidad para cargos, restricciones por departamento, vigencia de restricciones, responsable de revisión y trazabilidad. No conviertas el sistema en un expediente disciplinario, médico o financiero.

Separa dos campos:

- **Motivo visible para la junta:** explicación mínima y respetuosa, por ejemplo «Ha indicado que no desea aceptar cargos durante este período».
- **Nota restringida:** información administrativa necesaria, cifrada para destinatarios autorizados y ausente de búsquedas, dashboards y exportaciones generales.

Un nombre no elegible podrá aparecer deshabilitado en búsqueda, mostrando únicamente la razón autorizada. Impide su selección desde UI y motor de validación. No divulgues la razón fuera de la audiencia permitida ni distingas estados sensibles a través de errores públicos.

La elegibilidad es versionada. Si cambia durante una ronda, suspende el proceso afectado para resolución documentada; no elimines ni reasignes votos silenciosamente. Evalúa si procede anular y crear una nueva ronda con padrón/candidaturas actualizado. Un cambio posterior no altera informes históricos.

Permite cargar, recortar y reemplazar fotos con controles de formato, peso y dimensiones; elimina EXIF y metadatos de ubicación. Verifica contenido real y decodifica/recrea imágenes seguras. No uses reconocimiento facial. Limita originales y miniaturas al tenant y a usuarios autorizados. Las imágenes demo deben ser sintéticas o contar con licencia y consentimiento apropiados.

## 7. Importación Excel y administración masiva

Entrega una plantilla descargable `.xlsx`, importación `.xlsx` y CSV UTF-8, y exportación controlada del padrón. La plantilla tendrá columnas documentadas, ejemplos exclusivamente de demo y validaciones simples.

Flujo obligatorio: seleccionar archivo → validar límites y formato → elegir hoja y mapear columnas → previsualizar → detectar errores y posibles duplicados → decidir crear/actualizar/omitir → confirmar → ejecutar transacción o lotes recuperables → presentar resumen y archivo de errores.

Campos mínimos: identificador opcional de origen, nombres, apellidos, estado de miembro, elegibilidad, razón visible opcional y referencia opcional a foto. No exijas teléfonos, fechas de nacimiento, direcciones ni correos de todos los hermanos para poder votar por ellos. Cargar personas no crea cuentas de usuario automáticamente.

No ejecutes macros, fórmulas ni enlaces del archivo. Rechaza archivos malformados, volúmenes desmedidos y bombas de descompresión. Neutraliza inyección de fórmulas en CSV/Excel exportados. No descargues fotos desde URLs arbitrarias del archivo; cualquier mecanismo opcional deberá controlar SSRF y permisos.

Normaliza espacios y construye búsqueda insensible a acentos sin modificar el nombre visible. La deduplicación sugerida debe permitir revisión: no fusiones homónimos automáticamente. El reintento de una importación no debe duplicar personas; usa identificadores, huellas de importación e idempotencia.

En el diseño E2EE, el análisis y cifrado de datos personales sucede en el cliente autorizado, preferiblemente en un worker del navegador. El servidor valida envolturas, cuotas y metadatos sin recibir nombres en claro. Define cómo se realiza cada validación semántica en ese modelo y prueba importaciones grandes sin bloquear la UI.

## 8. Preparación de ciclos y sesiones

Permite crear un ciclo para el próximo mandato, clonar la estructura de uno anterior sin copiar votos ni asignaciones y registrar fechas de sesiones. Configura idioma, zona horaria, jurisdicción, paquete normativo, comité, roles, cargos aplicables y número de plazas.

El administrador o secretario puede ordenar la agenda y elegir libremente el siguiente cargo pendiente dentro de sus dependencias. Por defecto existirá una sola ronda activa por ciclo para que todos los participantes vean inequívocamente la misma elección. Si se habilita trabajo paralelo posteriormente, exige salas y padrones explícitos; no lo introduzcas por accidente.

Configura separadamente:

- Máximo de nombres propuestos por participante; se admite enviar menos y abstenerse explícitamente de proponer.
- Número de vacantes y máximo de selecciones en la boleta; no asumir que coincide con el máximo de propuestas.
- Regla de decisión interna, umbral aplicable, tratamiento de abstenciones y desempates. La interfaz permite abstenerse de votar; la regla validada determina su efecto en los denominadores, sin tratarla como voto a un candidato.
- Padrón de participantes obligatorios, elegibilidad de candidatos y reglas de recusación.
- Audiencias autorizadas de agregados y autorización de informes externos. La junta recibe los agregados al confirmarse el escrutinio; nunca durante la ronda abierta. Una publicación congregacional posterior es una acción diferente.
- Custodios, disponibilidad de claves y procedimiento de recuperación.
- Calendario, reglas de quórum y plazos procedentes de la normativa validada.

Congela estas condiciones al abrir una ronda. Conserva un hash de configuración y una versión del padrón. No permitas cambiar candidatos, plazas, límite de selecciones o denominador en medio de la votación.

«Todos participaron» se evalúa sobre el padrón congelado de la ronda, no sobre quién aparece conectado. Distingue pendiente, propuesta enviada, voto recibido, abstención registrada, ausencia y recusación. La conexión a Internet no confiere ni elimina derecho a voto.

La abstención explícita satisface la obligación de responder, sin convertirse en voto a un candidato. La ausencia no es abstención. Ante una ausencia no resuelta, permite pausar/reprogramar; cualquier excepción admisible deberá tener permiso específico, fundamento, motivo y auditoría. Si debe cambiar el padrón de una ronda abierta, anúlala y crea una versión nueva. No retires silenciosamente a personas pendientes para fabricar el 100 % de participación.

## 9. Máquina de estados y flujo central

Implementa una máquina de estados explícita. El servidor es autoridad sobre la fase, el cierre y la recepción; los clientes no pueden saltarse transiciones. Cada transición tendrá permisos, precondiciones, control de concurrencia y evento auditable.

```text
Cargo: PENDIENTE → CONFIGURADO → PROPUESTAS_ABIERTAS
       → PROPUESTAS_CERRADAS → DEPURACION → LISTA_CONFIRMADA
       → VOTACION_ABIERTA → VOTACION_CERRADA → ESCRUTINIO
       → RESULTADO_INTERNO → RECOMENDACION_CONFIRMADA → CERRADO

Rutas adicionales explícitas: PAUSADO, SIN_CANDIDATOS,
DESEMPATE_PENDIENTE, ANULADO, VACANTE_PENDIENTE.

Asignación: PROPUESTA_INTERNA → ACEPTACION_PENDIENTE → ACEPTADA
            → PRESENTADA_A_IGLESIA → ELEGIDA_POR_IGLESIA → VIGENTE
            → FINALIZADA.
Alternativas: DECLINADA, DEVUELTA_A_COMISION, RETIRADA, SUSTITUIDA.
```

La secuencia de consulta de disponibilidad y aceptación debe ajustarse al procedimiento aplicable; la representación anterior no obliga a esperar al escrutinio para pedir consentimiento. Separa estado del proceso, estado de cada ronda, estado de la candidatura y estado de la asignación.

### 9.1 Propuestas

Al abrir propuestas, todos los miembros habilitados reciben la actualización en vivo y ven departamento, cargo, plazas, funciones resumidas, límite de nombres y estado del paso.

Podrán escribir para buscar y seleccionar hermanos del padrón autorizado. No aceptes nombres libres fuera del padrón; la incorporación de una persona faltante requiere el flujo administrativo correspondiente antes de una ronda nueva. Muestra foto opcional, nombre completo, elegibilidad y responsabilidades ya asignadas que el usuario tenga permiso de consultar.

Impide seleccionar dos veces a la misma persona. Muestra chips o tarjetas seleccionadas, contador «2 de 3 propuestas» y acción para retirar una selección antes del envío. Permite enviar menos nombres que el máximo y una abstención explícita. Un borrador no cuenta como participación.

El envío requiere una confirmación breve y devuelve recibo opaco, fase, versión y hora. Una propuesta enviada será definitiva en esa ronda por defecto; cualquier política de reemplazo debe implementarse como versión explícita antes del cierre, contando solamente la última válida y preservando confidencialidad. No habilites edición retroactiva.

El administrador/secretario autorizado ve quién completó el paso y quién está pendiente, sin ver las elecciones individuales. Cuando todos respondan, habilita «Cerrar propuestas e iniciar depuración»; no cambia de fase sin la acción de cierre.

Tras cerrar y efectuar el recuento autorizado, consolida por identificador de candidato. Si cinco personas propusieron a la misma hermana, aparece una sola vez con «5 proponentes». El conteo es de participantes distintos y no de menciones, reintentos o variantes ortográficas.

### 9.2 Depuración

Presenta a la junta una lista única con foto/nombre, proponentes, porcentaje, disponibilidad, asignaciones actuales y ficha del cargo. Distingue el número de propuestas del número de votos.

Permite registrar evaluación, consulta, aceptación preliminar, retiro y exclusión justificada. Las razones visibles y notas restringidas siguen sus permisos. Cada decisión conserva autor, fecha y fundamento. El sistema organiza la revisión humana; no puntúa la espiritualidad ni recomienda automáticamente quién debería servir.

Solo candidaturas propuestas, elegibles y confirmadas pasan a la boleta. Si hace falta agregar candidatos nuevos, reabre mediante una nueva ronda de propuestas trazable. No insertes una candidatura oculta en una votación ya configurada.

Si no queda ningún candidato, marca `SIN_CANDIDATOS` y ofrece nueva propuesta o dejar pendiente. No inventes un ganador. Antes de votar, congela identificadores, reglas y plazas. Calcula el hash sobre una representación canónica independiente del idioma, ordenada por identificador. Fija aparte el orden visible de candidatos usando el idioma del ciclo y desempate estable por identificador, para que todos vean el mismo orden aunque cambien el idioma de la interfaz; no ordenes la boleta por popularidad.

### 9.3 Votación

La pantalla móvil muestra solamente candidaturas confirmadas y la opción de abstención. Para una vacante, una selección; para varias plazas homogéneas, hasta el límite configurado. Nunca permite votos duplicados por candidato dentro de la misma boleta ni más selecciones que el máximo.

No muestres conteos de preferencias durante la votación abierta. El tablero en vivo muestra participación, pendientes y estado de conexión; los resultados agregados se publican inmediatamente después del cierre y escrutinio autorizado. Esta es una decisión de producto para evitar influencia y filtraciones por diferencias entre eventos.

El servidor confirma una única recepción efectiva por elector y ronda mediante restricciones de unicidad y transacciones. Un doble toque, reintento HTTP, recarga o segunda pestaña no crea un segundo voto. La abstención excluye selecciones de candidatos. Las boletas malformadas se detectan y resuelven según el protocolo de validación cifrada, sin contarlas silenciosamente.

Cuando todos los electores requeridos respondan, el secretario o administrador con permiso puede cerrar. El cierre compite de forma atómica con envíos simultáneos: queda inequívocamente definido cuál fue recibido antes del cierre. Un envío tardío recibe una respuesta clara y no se presenta como recibido.

### 9.4 Escrutinio, empates y resultado interno

Implementa por defecto la pluralidad solicitada para ordenar el resultado interno: mayor cantidad de votos válidos. Esta preferencia debe validarse frente a las reglas de funcionamiento aplicables a la junta y no reemplaza la elección congregacional.

Para una plaza, solo puede recomendarse como resultado de esa regla al candidato con máximo único y votos mayores que cero. Si se exige mayoría absoluta o un umbral adicional, la regla configurada debe comprobarlo; liderar el conteo no basta. Para varias plazas, considera los primeros K con votos positivos y resuelve cualquier empate que afecte el último cupo. Si menos de K candidatos satisfacen las condiciones, las plazas restantes quedan pendientes; cerrar una ronda no completa automáticamente el cargo o departamento.

Un empate genera una nueva ronda de desempate entre los candidatos afectados. Nunca decidas por orden alfabético, edad, orden de llegada, azar o intervención oculta del administrador. Si continúa el empate, la resolución humana debe seguir la política validada y quedar documentada. Conserva rondas anteriores sin sumarlas a la final.

Si todas las boletas son abstenciones o no hay votos válidos a candidatos, no hay selección automática. Un candidato único sigue el mecanismo aprobado; no lo declares seleccionado por la mera ausencia de competencia.

La confirmación registra resultado, regla aplicada, evidencia del escrutinio, estado de aceptación y asignación provisional. Puede conservar un resultado interno con aceptación pendiente, pero solo permite incorporar personas al informe formal cuando satisfacen el consentimiento requerido. Antes de cerrar el cargo, muestra resumen verificable y permite continuar con el siguiente cargo pendiente.

### 9.5 Ancianos y primer anciano

Modela la selección del grupo de ancianos y posteriormente la designación de primer anciano entre quienes integran ese grupo conforme al procedimiento validado. La designación de primer anciano no crea una segunda persona ni borra su condición de anciano.

Representa la relación entre responsabilidad base y coordinación. El dashboard puede mostrar ambas funciones, pero su conteo de carga deberá identificar cuándo son responsabilidades vinculadas para no producir una alerta engañosa. La ordenación, cuando corresponda, tiene un registro independiente y no se presume realizada por haber recibido votos.

### 9.6 Informe, elección congregacional y vacantes posteriores

Genera el informe de recomendaciones con las aceptaciones requeridas. Registra presentación, versión, fechas, objeciones tratadas por el canal apropiado, devolución a la comisión y resultado de la elección por la iglesia. Los detalles de objeciones no pertenecen al reporte general.

Si una persona declina antes de presentar el informe, marca únicamente esa asignación como declinada, libera la plaza y abre un procedimiento vinculado para resolverla. Conserva sus propuestas y votos históricos sin transferirlos a otra persona ni sustituir automáticamente al ganador.

Permite registrar el acta y cómputo de una votación congregacional realizada fuera de esta aplicación. Si se desarrolla votación congregacional digital, será un módulo diferenciado con su propio padrón y reglas; no reutilices automáticamente a los miembros de la comisión como electorado de la iglesia.

Solo las asignaciones efectivamente elegidas y en su período aparecen como directiva vigente. Los organigramas preliminares deben decir «Propuesta de la junta» o «Pendiente de elección por la iglesia». Las renuncias y vacantes posteriores generan un procedimiento nuevo enlazado, sin reescribir el acta anterior ni promover automáticamente al segundo más votado.

## 10. Organigrama y distribución de responsabilidades

Entrega un organigrama general y uno por departamento, construidos a partir de asignaciones reales. Deben representar dirección, funciones asociadas, secretaría cuando corresponda, equipos e integrantes, además de vacantes pendientes. Ofrece vista gráfica y lista accesible equivalente, buscador, filtros por mandato/estado, zoom y exportación autorizada.

Cada nodo mostrará cargo, persona, foto opcional y estado. En celular, prioriza una lista jerárquica plegable con tarjetas; no obligues a manipular un lienzo ancho para conocer el departamento. Permite alternar propuesta de la junta y directiva elegida sin mezclar ambas.

Al asignar una segunda función nominal a una persona, genera un aviso informativo inmediato. Si representa una segunda responsabilidad independiente, destaca además la alerta de acumulación de carga. Muestra cuántas tiene, cuáles son, sus departamentos, relaciones y si son preliminares o vigentes. Los avisos no bloquean la asignación; permiten registrar que fueron considerados. Nunca crean una clasificación pública de popularidad o mérito espiritual.

Modela las responsabilidades vinculadas —por ejemplo, integrante y coordinador del mismo cuerpo— mediante una relación explícita. Muestra funciones nominales y cargas independientes por separado. Documenta la regla de conteo y conserva ambas medidas para evitar duplicaciones engañosas.

## 11. Dashboards en vivo y definiciones de métricas

Diseña tres experiencias: tablero de conducción para presidente/secretario, tablero personal de participación para cada miembro y tablero analítico de resultados e historial. Agrega una vista de operación global sin datos personales de iglesias.

Las tarjetas, gráficos y tablas utilizarán datos reales de la misma fuente de resultados. Cada métrica tendrá período, fase, filtros, denominador, versión y última actualización. Los estados vacíos son ceros o «No aplica» según corresponda; nunca valores demo ocultos.

| Métrica | Definición obligatoria |
| --- | --- |
| Participación del paso | Respuestas finales recibidas, incluidas abstenciones explícitas, divididas entre electores requeridos de la ronda congelada. Mostrar cantidad y porcentaje. |
| Pendientes | Electores requeridos sin respuesta final; lista nominal solo para quienes tengan permiso. Presencia en línea es una señal separada. |
| Proponentes de candidato | Número de participantes distintos que lo incluyeron en su propuesta válida vigente de esa ronda. |
| Apoyo en propuestas | Proponentes del candidato / participantes con propuesta válida no vacía. Mostrar aparte abstenciones de proponer. La suma puede superar 100 % si se permiten varios nombres. |
| Votos por candidato | Número de boletas válidas que incluyen al candidato; nunca total de solicitudes o clics. |
| Porcentaje electoral | Votos del candidato / boletas válidas no abstencionistas. Para selección múltiple, advertir que los porcentajes pueden sumar más de 100 %. |
| Participación sobre electorado | Si se muestra apoyo sobre todos los electores requeridos, será una métrica distinta y con ese denominador explícito. |
| Cobertura de vacantes | Vacantes con recomendación / vacantes aplicables configuradas. Mostrar separadamente aceptadas, elegidas por la iglesia y vigentes. |
| Avance de departamento | La misma fórmula restringida al departamento; mostrar, por ejemplo, «3 de 5 plazas recomendadas · 60 %». |
| Personas consideradas | Elegibles del universo de referencia que aparecen al menos una vez en propuestas válidas de rondas no anuladas del ciclo. No es una valoración de su idoneidad. |
| No consideradas | Elegibles del universo de referencia menos personas consideradas; cantidad y porcentaje sobre ese mismo universo. |
| Personas sin cargo | Elegibles sin asignación en el estado seleccionado; distinguir sin recomendación y sin cargo elegido. No equivale a «nunca propuestos». |
| Concentración | Personas únicas con dos o más responsabilidades independientes; listar responsabilidades y distribución de carga. |
| Distribución de carga | Personas con 0, 1, 2, 3 o más responsabilidades; distinguir cargos nominales y responsabilidades vinculadas. |
| Proceso | Cargos pendientes, en propuestas, en depuración, en votación, empatados, recomendados, aceptados y concluidos; tiempos por fase. |
| Calidad de padrón | Miembros totales, elegibles, no disponibles, posibles duplicados y registros que requieren revisión, según permisos. |

Congela un universo de elegibles de referencia al iniciar el ciclo y etiqueta los cambios posteriores. Ofrece, si hace falta, comparación con el padrón actual como otra vista; no cambies silenciosamente el denominador histórico. Un denominador cero produce «No aplica», no `NaN`, infinito ni un 100 % engañoso.

Incluye gráficos de barras legibles para propuestas/votos, progreso por departamento, distribución de responsabilidades, evolución por sesiones y tabla de detalle con filtros. Evita gráficos 3D, animaciones ornamentales, arcoíris y decimales innecesarios. Cada gráfico tendrá alternativa tabular, títulos precisos y controles que respeten permisos.

El modo proyección para la junta omite notas privadas, contactos y detalles de autenticación. El modo de informe congregacional contiene únicamente información autorizada para esa audiencia. No existe un enlace público al tablero de deliberaciones.

Los eventos en vivo mostrarán fase y participación en pocos segundos, con reconexión y recuperación de eventos perdidos. El dashboard no deduce preferencias a partir de eventos por candidato durante una ronda abierta, ni siquiera mediante endpoints ocultos o diferencias en respuestas de API.

## 12. Reportería institucional completa

Implementa un centro de reportes con filtros por tenant autorizado, ciclo, mandato, sesión, departamento, cargo, persona, fase y estado de asignación. El selector de tenant solo aparecerá a quien corresponda y no elude el control de acceso.

Reportes obligatorios:

1. Informe general de recomendaciones: todos los departamentos, cargos, cabezas e integrantes, aceptaciones y pendientes.
2. Directiva elegida: nombres, responsabilidades y mandato; versión preparada para presentación a la iglesia.
3. Departamento: organigrama, plazas cubiertas/pendientes y responsables.
4. Cargo y ronda: candidaturas, proponentes, votos, porcentajes, abstenciones, regla aplicada y desenlace.
5. Participación de la junta: quiénes integraron el comité, funciones, asistencia y cumplimiento de pasos, sin preferencias individuales.
6. Distribución de responsabilidades: personas con varios cargos, alertas consideradas y funciones vinculadas.
7. Elegibles no considerados y personas sin cargo, con definiciones separadas.
8. Avance general y por departamento, con todos los denominadores.
9. Acta de sesiones y decisiones, presidente/pastor, secretario, fechas, acuerdos y versiones.
10. Historial de ciclos y comparación entre mandatos con métricas comparables.
11. Auditoría de acciones y verificaciones de integridad para perfiles autorizados.
12. Padrón e incidencias de importación, disponibles solo a administradores autorizados.

Ofrece PDF profesional, `.xlsx`, CSV y vista imprimible. Usa un diseño sobrio: identidad autorizada, nombre de iglesia, período, título, filtros, tablas legibles, encabezados repetidos, paginación, fecha de generación y clasificación de audiencia. Prueba nombres largos, tablas multipágina, caracteres acentuados y los tres idiomas. No cortes filas de forma ilegible ni exportes solamente una captura del dashboard.

Los reportes internos de votos pueden incluir agregados, pero jamás relaciones elector–candidato. Las versiones congregacionales omiten conteos internos, elegibilidad, notas, deliberaciones y motivos de exclusión salvo una política explícita y legítima para esa audiencia.

Toda exportación requiere permiso específico y deja evento de auditoría. Usa descargas autenticadas o enlaces breves revocables para archivos cifrados; no publiques documentos por conocer una URL. Notifica cuando un archivo ya no está disponible y permite regenerarlo si hay autorización.

En el perfil E2EE, el documento en claro se genera en un cliente autorizado; los trabajos de servidor solo preparan artefactos cifrados o metadatos. Si se introduce un servicio que descifra para exportar, documenta que pasa a ser un destinatario de confianza y que cambia la propiedad E2EE: no lo actives de forma implícita.

Conserva versión del informe, instantánea de nombres/cargos, reglas y resultados usados. Un cambio posterior de nombre, traducción o estructura no altera documentos históricos emitidos. Una corrección genera nueva versión con vínculo a la anterior.

## 13. Historial y auditoría resistente a manipulación

Registra operaciones relevantes: acceso, fallos de autenticación, invitaciones, cambios de permisos, importaciones, elegibilidad, configuración, apertura/cierre, recibos de participación, depuración, escrutinio, confirmaciones, consultas sensibles, exportaciones, recuperación y administración de tenants. No registres cada tecla ni conviertas telemetría en vigilancia innecesaria.

Los eventos incluirán identificador, tenant, secuencia, fecha UTC del servidor, actor o seudónimo autorizado, acción, entidad/versión, resultado, motivo cuando corresponda, correlación y referencia a evidencia. Conserva las sesiones reales y sus fechas en la zona horaria de la iglesia.

La bitácora no contendrá contraseñas, claves, tokens, nombres de candidatos asociados a votantes, cuerpos de boletas, notas privadas ni contenido de documentos. Una auditoría de cambio sensible almacena referencia y versión cifrada, no una copia en claro de los valores antes/después.

Implementa escritura append-only con credenciales separadas, secuencias, serialización canónica, encadenamiento de hashes, firma de puntos de control y anclajes en un almacén independiente con retención WORM. Una tabla «sin botón de borrar» o una cadena de hashes que un administrador puede recalcular no son evidencia suficiente de inmutabilidad. [Orientación técnica sobre registros seguros](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

Define el alcance de la garantía: prevenir cambios ordinarios y detectar alteración, borrado, truncamiento, reordenación o restauración de una copia antigua. No prometas invulnerabilidad frente a quien controle toda la infraestructura, todas las claves y todos los anclajes. Si el entorno local no proporciona WORM real, identifícalo como capacidad emulada de desarrollo y exige la validación del destino real para producción.

Incluye una herramienta de verificación de integridad y un reporte entendible. Prueba la detección modificando una copia de prueba, eliminando eventos, truncando la cola y restaurando un respaldo anterior. No ensayes destrucción sobre datos reales.

Define retención por categoría, custodia de actas y tratamiento de solicitudes de rectificación o eliminación conforme a la jurisdicción validada. Mantén mínima la información personal en registros inmutables; usa correcciones anexas y procedimientos documentados cuando conservar la evidencia y proteger privacidad entren en tensión.

## 14. Diseño visual, identidad y navegación

Usa como referencias verificables el [sitio de la Asociación General](https://gc.adventist.org/), el [sitio mundial adventista](https://adventist.org/) y el [sistema oficial de identidad](https://www.adventist.design/). Inspecciona su estado actual al diseñar y documenta los elementos que tomas como referencia. Traduce su carácter institucional a una aplicación de trabajo de alta calidad.

Emplea recursos oficiales del [logo adventista](https://www.adventist.design/downloads/logo/) y respeta sus proporciones, espacio de protección, idioma y variantes. Verifica las [condiciones oficiales de uso de marcas](https://adventist.org/trademark-and-logo-usage). El producto no debe sugerir patrocinio o certificación de la Asociación General sin que exista. No redibujes el símbolo ni lo conviertas en icono ornamental.

La tipografía solicitada es **Advent Sans**. Descarga los recursos oficiales, verifica glifos y licencias y conserva los avisos; el [toolkit oficial](https://www.adventist.design/downloads/toolkit/) identifica Advent Sans bajo SIL Open Font License. Distingue la variante para logotipos de una fuente adecuada para texto continuo. Prioriza Advent Sans donde su variante funcione correctamente y usa una alternativa compatible como Noto Sans si falta cobertura o legibilidad, documentando el motivo y preservando la identidad. [Guía oficial Advent Sans](https://www.adventist.design/global-elements/advent-sans/).

Construye un sistema de diseño propio: tokens semánticos de color, tipografía, espaciado, radios, sombras, bordes, foco, estados y densidad. Como dirección inicial de producto, considera azul profundo, neutros claros y acentos moderados; valida los colores finales contra la identidad y el contraste, sin llamarlos oficiales por defecto.

El diseño debe ser limpio y digno: jerarquía clara, espacio suficiente, números fáciles de leer, iconografía consistente y animaciones breves con propósito. Evita fondos que dificulten la lectura, decoración religiosa repetitiva y exceso de texto. La profundidad analítica vive en filtros y detalle progresivo, sin saturar el primer pantallazo.

Navegación de escritorio según permisos: Resumen, Sesión en curso, Miembros, Departamentos y cargos, Junta, Organigrama, Reportes, Historial y Configuración. El administrador global tendrá un espacio separado para iglesias y operación. No mezcles controles globales con el panel ordinario de la junta.

En celular, prioriza «Sesión», «Mi participación», «Resultados» y «Más», ajustados al rol. La pantalla inicial de un miembro conduce directamente a su tarea pendiente; la del secretario muestra el cargo activo y las acciones de conducción.

Diseña y termina estados de carga, vacío, permiso insuficiente, sesión vencida, error, desconexión, datos obsoletos, no elegible, enviado, pendiente de escrutinio, empate y éxito. No dependas de mensajes temporales para información crítica.

## 15. Experiencia móvil de propuesta y voto

El flujo debe poder completarse con una mano, sin desplazamiento horizontal y con nombres legibles. Usa objetivos táctiles de 44–48 CSS px o mayores como meta de producto, tipografía base cómoda y áreas seguras del dispositivo. No confundas esta meta con el mínimo normativo de WCAG.

Estructura sugerida:

1. Encabezado compacto con iglesia, cargo, fase y estado de conexión.
2. Resumen «Selecciona hasta N personas», con acceso discreto a funciones del cargo.
3. Búsqueda y lista de tarjetas con foto opcional, nombre y estado.
4. Selección persistente visible y contador; la inelegibilidad se explica al intentar consultar una opción deshabilitada.
5. Acción principal fija que no tape contenido, teclado ni foco; confirmar antes de enviar.
6. Recibo claro de recepción, hora y próximo paso, sin contenido de voto en el comprobante.

El usuario sabrá si su selección es borrador, se está enviando, fue recibida o necesita reintento. No muestres éxito por una actualización optimista antes del acuse del servidor.

Ante pérdida de conexión, conserva un borrador temporal cifrado cuando sea viable y autorizado; no almacenes boletas en texto plano en `localStorage`. La reconexión consulta primero la fase y versión del servidor. Nunca sincronices ciegamente un voto offline después del cierre. Ofrece revisión antes de reenviar cuando cambien las condiciones.

Una app PWA instalable es deseable; la shell puede funcionar sin red, pero las decisiones requieren confirmación en línea. El service worker no cachea respuestas privadas en claro ni comparte datos entre usuarios. Cerrar sesión limpia material sensible local conforme a la política de dispositivos.

Prueba al menos iOS/Safari y Android/Chrome soportados, escritorio con teclado y pantallas desde 320 CSS px. Un emulador ayuda, pero no reemplaza toda comprobación en dispositivos reales cuando estén disponibles.

## 16. Accesibilidad e idiomas completos

La accesibilidad forma parte de la interfaz base. Apunta a **WCAG 2.2 AA**, con teclado, foco visible y no tapado, estructura semántica, contraste, ampliación, reflujo, nombres accesibles, errores vinculados a campos y alternativas a gestos complejos. Las pruebas automáticas se complementan con revisión manual. [Norma WCAG 2.2](https://www.w3.org/TR/WCAG22/).

Incluye preferencias persistentes para tamaño de texto, contraste reforzado, reducción de movimiento, densidad cómoda y tema claro/oscuro si ambos se validan. No uses un overlay de accesibilidad como sustituto de corregir componentes. Comprueba lectores de pantalla, organigramas en lista y gráficos con datos tabulares. Los cambios en vivo no deben inundar anuncios `aria-live` ni mover el foco sin causa.

Entrega español, inglés y francés completos: navegación, permisos, formularios, validaciones, estados, notificaciones, invitaciones, autenticación, catálogos, funciones, ayuda, accesibilidad y reportes. Español será el idioma inicial de Ozama; cada usuario podrá elegir el suyo sin alterar el idioma de otros.

Centraliza mensajes mediante una biblioteca de internacionalización con plurales y formatos locales. No traduzcas nombres propios ni identificadores. Guarda tiempos en UTC y muestra fechas en la zona del tenant, usando `America/Santo_Domingo` como configuración inicial de Ozama pendiente de confirmación administrativa.

Mantén un glosario ES/EN/FR para comisión/junta, anciano, diaconisa, nombramiento, recomendación y elección. No presentes traducciones generadas como traducciones oficiales de los manuales. Revisa semántica institucional y expansión de texto francés. El build debe detectar claves faltantes; no se aceptan pantallas finales con textos de relleno o mezcla accidental de idiomas.

## 17. Arquitectura técnica y versiones

Propón e implementa una arquitectura proporcionada al producto: **monolito modular con workers independientes**, límites claros de dominio y posibilidad de extraer microservicios cuando exista una necesidad demostrada. La robustez no depende de multiplicar servicios. Conserva integridad transaccional del ciclo electoral y evita duplicar lógica entre procesos.

Stack inicial recomendado, sujeto a comprobación técnica al implementar:

| Capa | Orientación |
| --- | --- |
| Lenguaje/runtime | TypeScript estricto sobre una versión Node.js LTS soportada. |
| Web | React y Next.js estables soportados; adaptación móvil y PWA segura. |
| API | NestJS con Fastify, o alternativa mantenida justificada; módulos de dominio, validación y autorización central. |
| Datos | PostgreSQL con una base y credencial por iglesia; migraciones versionadas con ORM/herramienta seleccionada mediante ADR. |
| Contratos | Esquemas de validación compartidos, OpenAPI y clientes tipados; DTO separados de entidades internas. |
| Tiempo real | SSE o WebSocket autenticado, con secuencia, reanudación y control de audiencia. |
| Trabajos | Cola durable y workers para aprovisionamiento, notificaciones, preparación de archivos cifrados y mantenimiento. |
| Archivos | Almacén de objetos privado; cifrado y políticas por tenant; WORM donde corresponda. |
| UI | Componentes accesibles y estilizados, tablas y gráficos mantenidos, sin dependencia obligatoria de planes pagos. |
| Pruebas | Herramienta unitaria mantenida, integración contra PostgreSQL real, Playwright, axe y carga reproducible. |
| Operación | Contenedores, configuración de desarrollo reproducible, CI, métricas sin datos sensibles y backups probados. |

A la fecha de preparación, Node.js 24 aparece como LTS y Next.js 16 como línea soportada activa; vuelve a verificar los parches y compatibilidades al comenzar. Registra versiones exactas, fecha y fuentes en `docs/dependencies.md`, conserva lockfile y evita `latest` flotante en artefactos de despliegue. [Versiones Node.js](https://nodejs.org/en/about/previous-releases), [política de soporte Next.js](https://nextjs.org/support-policy).

Estructura orientativa:

```text
apps/web                 # experiencia de usuario y operaciones criptográficas cliente
apps/api                 # autenticación, permisos, metadatos, estados y recepción
apps/worker              # trabajos durables con contexto explícito de tenant
packages/domain          # reglas, estados, métricas y tipos del dominio
packages/contracts       # DTO y esquemas públicos versionados
packages/database        # migraciones y resolución segura de conexiones
packages/crypto          # integración de bibliotecas revisadas; no primitivas caseras
packages/ui              # sistema de diseño accesible
packages/i18n            # mensajes y glosario ES/EN/FR
packages/catalog         # catálogos normativos versionados y procedencia
packages/testing         # fixtures y utilidades de integración
infra                    # contenedores, despliegue, backups y observabilidad
docs                     # decisiones, fuentes, operación, seguridad y guías
```

Si el repositorio existente exige otra estructura, intégrate sin duplicarlo innecesariamente. Un servidor HTTP de Next.js y una API separada requieren una justificación operativa clara y un flujo de sesión coherente; evita dos implementaciones rivales del dominio.

Usa transacciones, restricciones de unicidad, control optimista de versiones y bloqueos donde sean necesarios para apertura/cierre y recepción. Aplica patrón outbox para eventos que deban publicarse después de confirmar una transacción; los consumidores serán idempotentes. No dependas de la memoria de un proceso para preservar votos o determinar fase activa.

Controla los pools por tenant para no agotar conexiones. Nunca uses una conexión privilegiada compartida para solicitudes ordinarias. Las cachés de frontend, backend y framework deben estar correctamente acotadas o deshabilitadas para contenido privado; prueba expresamente que SSR, prerender y caché de rutas no mezclan usuarios ni iglesias.

## 18. Modelo de datos y contratos de API

Documenta y migra al menos las siguientes entidades, adaptando el nombre a la implementación:

```text
Control: Tenant, ProvisioningJob, PlatformIdentity, TenantMembership,
         SecretReference, PlatformAuditEvent.

Tenant: UserProfile, Role, Permission, RoleBinding, Member,
        MemberEligibilityVersion, PrivateNoteEnvelope, PhotoAsset,
        DepartmentDefinition, OfficeDefinition, NormativeReference,
        CatalogVersion, ElectionCycle, Term, CommitteeMembership,
        MeetingSession, Attendance, Vacancy, OfficeProcess,
        Round, RoundElectorSnapshot, CandidateSnapshot,
        ParticipationReceipt, EncryptedSubmission, CandidateReview,
        TallyManifest, SignedAggregate, CandidateConsent,
        Assignment, CongregationalDecision, ReportVersion,
        AuditEvent, AuditCheckpoint, DeviceKey, KeyGrant, OutboxEvent.
```

La separación entre recibos nominales y contenidos cifrados no debe deshacerse mediante una vista o endpoint administrativo. Los identificadores de persona, usuario, elector y candidato son conceptos distintos. Establece claves foráneas donde sea posible, índices, restricciones, política de borrado y versiones de esquema.

Garantiza una sola asignación efectiva por vacante y mandato, y evita que la misma persona ocupe dos plazas homogéneas del mismo cargo en ese mandato. Las asignaciones sustituidas se conservan como historia sin competir con la efectiva. Las funciones vinculadas, como primer anciano, referencian la asignación base mediante una relación explícita.

Modela datos personales y textos de iglesia como envolturas cifradas cuando lo exige la sección E2EE. Las columnas de metadatos en claro deben estar enumeradas en el modelo de amenazas. No envíes entidades completas al cliente ni incluyas propiedades restringidas porque el frontend «no las muestra».

Expón contratos para: onboarding de iglesia, membresías, roles, importaciones, catálogo, ciclos/sesiones, padrón de ronda, abrir/cerrar propuestas, enviar propuesta, consultar participación, depurar, confirmar candidatos, abrir/cerrar votación, enviar boleta, escrutinio, agregados, consentimiento, asignaciones, elección congregacional, organigramas, reportes y auditoría.

Las mutaciones críticas aceptarán identificador de idempotencia y versión esperada. Los errores deberán diferenciar autenticación, falta de permiso, fase incorrecta, conflicto de versión, ronda cerrada, límite excedido y fallo transitorio sin revelar información de otros tenants. Incluye contratos de eventos y política de reintentos; no uses un endpoint genérico de «actualizar cualquier estado».

## 19. Cifrado de extremo a extremo: alcance y funcionamiento real

El objetivo es proteger los contenidos personales y deliberativos desde el dispositivo emisor hasta los dispositivos de destinatarios autorizados. TLS, cifrado de discos y claves en un KMS controlado por el backend son controles necesarios, pero por sí solos **no constituyen E2EE**. No etiquetes como E2EE un sistema donde el servidor posee las claves de descifrado de los contenidos que promete proteger.

Antes de implementar, entrega un modelo de amenazas y una matriz de clasificación, almacenamiento, cifrado, destinatarios y ciclo de vida de claves. La configuración objetivo será:

| Categoría | Tratamiento y destinatarios |
| --- | --- |
| Identidad de autenticación y metadatos de operación | Mínimos datos necesarios en servicios de confianza, protegidos en tránsito y reposo. No se declaran E2EE. Incluyen identificadores opacos, fase, cuotas y recibos de participación. |
| Nombres, padrón y fotos | E2EE hacia dispositivos autorizados del tenant; la junta recibe únicamente los campos necesarios. Búsqueda sobre datos descifrados localmente. |
| Razones visibles de disponibilidad | E2EE para el ámbito autorizado de junta; separadas de las notas restringidas. |
| Notas privadas y deliberaciones | E2EE con claves y destinatarios más restringidos; no basta esconder un campo que todos pueden descifrar. |
| Propuestas y boletas | Cifradas en el cliente para custodios de la ronda. El backend recibe criptogramas y confirma recepción sin conocer selecciones. |
| Escrutinio y agregados | Cálculo en clientes custodios; manifiesto y agregados firmados. Contenido publicado cifrado para la audiencia autorizada. |
| Actas, organigramas e informes internos | E2EE en almacenamiento y distribución; descifrado y exportación en clientes autorizados. |
| Reporte para la iglesia | Publicación deliberada de una versión mínima autorizada; el documento exportado puede estar en claro y deja de tener la protección de la aplicación. |
| Auditoría | Metadatos mínimos sin contenido secreto; evidencia criptográfica y referencias a información cifrada. |

El resultado será una aplicación con E2EE de categorías expresamente definidas, no una afirmación imprecisa de que todo byte del sistema es invisible para el servidor. Documenta qué metadatos siguen siendo observables y las inferencias posibles en comités pequeños.

### 19.1 Claves y destinatarios

Utiliza bibliotecas y formatos criptográficos mantenidos y revisados. Web Crypto proporciona primitivas y no reemplaza un protocolo de aplicación bien diseñado; una sealed box tampoco equivale a un sistema electoral verificable. No inventes algoritmos, esquemas de reparto de secretos o pruebas criptográficas. [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/), [documentación de sealed boxes de libsodium](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

Registra en un ADR las bibliotecas, primitivas, versiones, formatos de envoltura y límites de confianza. Emplea cifrado autenticado con gestión segura de nonces y vinculación de contexto: tenant, ciclo, ronda, propósito, versión de esquema y hash de candidatos/reglas. Rechaza criptogramas alterados o reutilizados en un contexto diferente.

Genera y custodia claves privadas en dispositivos autorizados, con envolturas seguras y mecanismos de desbloqueo adecuados. El servidor puede almacenar claves públicas y copias cifradas de recuperación, pero no disponer de una clave universal que descifre todas las iglesias. Las claves de un tenant no abren contenido de otro.

Los clientes verificarán la autenticidad de claves públicas y concesiones de dispositivos mediante una cadena de confianza aprobada por el tenant o una verificación inicial por un canal independiente. Una respuesta de la API no basta para autenticar una clave: la sustitución, incorporación y rotación deben validarse antes de cifrar para un destinatario nuevo.

Implementa alta de dispositivo, confirmación de pertenencia, concesión criptográfica de acceso por un responsable autorizado, rotación, revocación, recuperación y destrucción según retención. Asignar un rol en una base de datos no debe bastar para que el administrador global obtenga claves de contenido.

La recuperación de contraseña no recupera mágicamente las claves E2EE. Diseña un flujo separado con material de recuperación protegido y custodia documentada. Si se pierden todas las claves y copias de recuperación, el contenido afectado puede resultar irrecuperable; el producto debe gestionar ese caso sin una puerta trasera oculta.

La revocación impide nuevos accesos y rota claves futuras; no puede borrar información que un destinatario legítimo ya haya copiado. Documenta esta limitación y minimiza los datos entregados. No guardes claves privadas, boletas ni padrones en claro en logs, bundles, analytics, service workers o almacenamiento persistente inseguro.

### 19.2 Escrutinio E2EE compatible con dashboards

Implementa un modo de custodia explícito y operativo. Una opción aceptable es cifrado hacia custodios autorizados y recuento en sus dispositivos, con dos verificaciones independientes del mismo conjunto cerrado de boletas antes de publicar el resultado. La interfaz debe guiar preparación de claves, prueba de recuperación y disponibilidad antes de abrir una ronda.

En ese modo, los custodios son destinatarios de confianza y pueden acceder al contenido descifrado para contar. No prometas secreto criptográfico frente a ellos, anonimato absoluto ni imposibilidad matemática de descifrado anticipado solo porque un botón esté deshabilitado. El protocolo y la política de custodia deben declarar sus supuestos.

Si se exige ocultar incluso a custodios cada selección individual o imponer un umbral criptográfico, integra un protocolo electoral establecido y revisado que ofrezca esas propiedades. Evalúa compatibilidad real con navegador, selecciones múltiples, abstenciones y recuperación. No improvises criptografía para cumplir una etiqueta. Una limitación no resuelta debe registrarse como tal y nunca sustituirse silenciosamente por votos en claro.

Flujo mínimo de escrutinio:

1. Cerrar atómicamente la ronda y fijar conjunto de recibos/criptogramas, configuración y versión.
2. Crear manifiesto verificable del conjunto cerrado, sin asociar públicamente identidad y preferencias.
3. Entregar las boletas cifradas exclusivamente a los custodios y solo en la fase permitida por la aplicación.
4. Descifrar y validar contexto, integridad, esquema, candidatos permitidos, cardinalidad, duplicados y abstención en el cliente autorizado.
5. Recontar de forma determinista; conciliar cantidad recibida, válidas, abstenciones y anomalías.
6. Obtener verificaciones/firma de custodios según la política. Si difieren, detener publicación y mostrar incidencia.
7. Publicar agregado firmado y cifrado para los usuarios autorizados; los clientes verifican firmas y manifiesto antes de mostrarlo como confirmado.
8. Registrar la transición y evidencias mínimas, manteniendo boletas y claves bajo su retención definida.

Si la validación semántica solo puede realizarse tras descifrar, la API debe distinguir «criptograma recibido» de «boleta válida». Una selección ilegal o boleta corrupta no se descarta discretamente cambiando el resultado. Marca incidencia, aplica la política documentada y, cuando corresponda, anula y repite la ronda. Si se adopta validación criptográfica previa, utiliza pruebas de validez de un protocolo establecido, no validaciones falsas sobre datos inaccesibles.

Vincula cada acuse al criptograma aleatorizado recibido mediante un identificador autenticado o su hash. El manifiesto cerrado debe permitir verificar inclusión y conciliar todos los acuses emitidos, detectando omisiones, sustituciones y duplicados sin revelar preferencias. Dos custodios que cuentan lo mismo no detectan por sí solos una boleta omitida de ambos conjuntos. La prueba de inclusión confirma recepción en el conjunto, no todas las propiedades de una elección verificable de extremo a extremo.

Mantén separados los canales de participación nominal y resultados. No publiques un hash de una elección en claro que permita probar a quién se votó; los recibos identifican recepción opaca. No permitas exportaciones con vínculos elector–preferencia. Documenta que metadatos temporales y colusión de componentes pueden permitir inferencias; no vendas verificabilidad o resistencia a coacción que no se haya implementado.

### 19.3 Búsqueda, analítica y exportaciones cifradas

La búsqueda de nombres, cálculo de métricas personales y generación de informes sucederán en el navegador autorizado sobre datos descifrados allí. Optimiza con índices locales en memoria/workers y descarga paginada de conjuntos cifrados autorizados. Las cachés persistentes opcionales estarán cifradas y sujetas a expiración y cierre de sesión.

Antes de afirmar que un miembro no existe, completa el índice de búsqueda del padrón autorizado. Mientras esté incompleto, muestra que continúa cargando y no presenta ausencia de coincidencias como resultado definitivo. Las fotografías y otros datos voluminosos pueden cargarse bajo demanda.

El backend puede contar recibos, fases y plazas usando metadatos mínimos; no calculará preferencias sobre boletas E2EE sin un protocolo que realmente lo permita. Un worker que descifra con una clave del servidor contradice ese alcance y no es una optimización aceptable sin cambiar explícitamente el modelo.

Protege la entrega del cliente con controles de cadena de suministro, CSP, dependencias restringidas y artefactos de despliegue verificables. El E2EE de una app web tiene límites frente a un servidor que distribuya código malicioso o a un dispositivo comprometido; descríbelos en el modelo de amenazas y no afirmes garantías absolutas.

## 20. Autenticación, privacidad y seguridad general

Exige MFA al administrador global y a los administradores de tenant antes de ejercer privilegios; ofrécelo a todos y permite exigirlo a la junta. Implementa passkeys/WebAuthn cuando la solución de identidad lo soporte y TOTP como alternativa, con códigos de recuperación de un solo uso y flujo de recuperación auditable. No desarrolles desde cero un sistema de autenticación criptográfica.

Las cuentas se crean mediante invitaciones con caducidad, destinatario y tenant determinados. Evita contraseñas compartidas, cuentas genéricas de votantes y sesiones comunes en un mismo celular. Una persona puede tener más de un dispositivo, pero conserva un único derecho de respuesta por ronda.

Implementa sesiones revocables, cookies seguras `HttpOnly` y `SameSite` apropiadas, protección CSRF según el modelo de sesión, límites de intentos y envío, detección de abuso, comprobación de origen de conexiones en vivo y prevención de fijación de sesión. No almacenes tokens de sesión de larga duración en `localStorage`.

Reautentica operaciones sensibles: cambios de administradores, recuperación de claves, exportación amplia y configuración de seguridad. La caducidad de sesión no debe convertir un voto no confirmado en voto recibido ni causar su repetición.

Aplica validación estricta de entrada, consultas parametrizadas, autorización por objeto, protección XSS, CSP, encabezados seguros y validación de archivos. Mantén secretos fuera de repositorios, imágenes de contenedor y registros. Separa secretos de despliegue, migraciones, ejecución, backups y firma de auditoría.

El objetivo de ingeniería es cumplir los controles aplicables de **OWASP ASVS nivel 2**, con análisis y controles reforzados para votación, claves, privilegios y aislamiento. Entrega una matriz con evidencia y justificación de controles no aplicables; no anuncies certificación automática por usar bibliotecas conocidas. [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/), [seguridad multi-tenant de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html).

Los datos revelan pertenencia religiosa y decisiones internas; minimiza su tratamiento. Define responsable por tenant, finalidad, base aplicable, consentimiento/autorización de fotos cuando corresponda, residencia de datos, proveedores, retención y canales para derechos. Identifica y verifica la legislación de las jurisdicciones reales con asesoría competente; no presupongas que un estándar técnico equivale a cumplimiento legal.

No incluyas rastreadores publicitarios, grabaciones de sesión, analítica que capture formularios o envío de padrones a servicios de IA. Las notificaciones por correo, si se usan, contendrán información mínima y enlaces autenticados, no votos o deliberaciones. La demo no debe enviar correos a direcciones reales.

Incluye gestión de vulnerabilidades, actualizaciones automatizadas con revisión, inventario de componentes/licencias, SBOM, escaneo de secretos y análisis de dependencias. Corrige hallazgos críticos y altos pertinentes antes de declarar listo para producción; una excepción necesita una justificación y aceptación de riesgo explícitas, nunca silencio.

## 21. Operación, rendimiento y continuidad

Entrega desarrollo local reproducible con contenedores y documentación; ambientes separados de desarrollo, pruebas y producción; CI con checks relevantes; migraciones seguras y despliegues reversibles. El despliegue local no debe depender de una suscripción de pago para recorrer el flujo completo.

Documenta configuración de dominio/TLS, correo de invitaciones, secretos, almacenamiento, WORM, backups y claves. En local puede haber buzón de pruebas y servicios compatibles; identifica qué se simula y qué se valida contra infraestructura real. No declares alta disponibilidad porque existan archivos de contenedores.

Implementa copias por tenant, cifrado, inventario de versiones de claves y restauración aislada. Prueba recuperar una iglesia sin sobrescribir otra. La restauración debe preservar coherencia entre base, archivos cifrados, claves recuperables, manifiestos y anclajes de auditoría.

Objetivos iniciales de operación, a validar sobre un entorno documentado:

- Escenario mínimo de carga: 10 tenants concurrentes, 50 participantes por tenant y padrón de hasta 10.000 miembros por iglesia.
- Acuse de recepción de propuestas/votos: p95 menor de 1,5 s en condiciones de prueba definidas, excluida indisponibilidad de red del usuario.
- Propagación de fase y participación: p95 menor de 2 s después de confirmar la transacción.
- Búsqueda local: respuesta perceptible menor de 300 ms con índice disponible; medir también descarga inicial y descifrado.
- Metas web: LCP ≤ 2,5 s, INP ≤ 200 ms y CLS ≤ 0,1 en escenario móvil documentado. Son presupuestos de producto, no resultados ya obtenidos.
- Objetivos operativos iniciales: RPO ≤ 15 min y RTO ≤ 4 h con un procedimiento e infraestructura que los hagan posibles; medirlos en una restauración de ensayo.

Publica resultados medidos, hardware, red, conjunto de datos y límites; no ocultes fallos bajo porcentajes agregados. Ajusta capacidad y diseño si no se cumplen objetivos, y explica cualquier desviación.

Observabilidad: salud, disponibilidad, latencias, cola, fallos de aprovisionamiento, errores de autorización y anomalías de recuento. Utiliza IDs de correlación sin contenido personal. La administración global puede consultar salud de tenants sin abrir su padrón o sus informes.

Entrega procedimientos para incidente de seguridad, pérdida de conexión, caída durante escrutinio, pérdida de dispositivo, recuperación de claves, sustitución de administrador y reanudación de una sesión. El soporte no debe emitir votos por un miembro ni suplantar su participación.

## 22. Demostración real y datos sintéticos coherentes

La demo debe recorrer el mismo backend, persistencia, permisos, cifrado y motor de reglas que el tenant real. Los datos seed son sintéticos; las interacciones posteriores son reales. No implementes una UI paralela basada en constantes para aparentar funcionalidad.

Incluye un ciclo actual y al menos dos ciclos históricos, comité con presidente/pastor y secretario, departamentos completos y pendientes, propuestas repetidas consolidadas, candidatos no disponibles, homónimos, fotos opcionales, abstenciones, empate, rechazo de cargo y personas con varias responsabilidades. Simula incidentes solamente en escenarios controlados identificados como demo.

Fixture determinista de referencia para validar fórmulas:

| Dato de demo | Valor y resultado esperado |
| --- | --- |
| Padrón del ciclo | 180 miembros sintéticos, 150 elegibles de referencia. |
| Junta de una ronda | 7 electores requeridos; 6 propuestas no vacías y 1 abstención de proponer = 100 % de respuesta. |
| Propuestas a A/B/C | 4/3/2 proponentes distintos; 66,67 % / 50 % / 33,33 % sobre los 6 proponentes efectivos. |
| Votación de una plaza | A=3, B=2, C=1, una abstención; 7 recibidos y 6 boletas no abstencionistas; A tiene 50 % sobre esas 6. |
| Resultado según regla | Con pluralidad interna, A tiene máximo único. Con mayoría estricta superior al 50 %, A todavía no alcanza el umbral. |
| Cobertura de ciclo | 40 vacantes aplicables; 20 recomendadas = 50 %. De ellas, 15 con aceptación y 10 elegidas por la iglesia. |
| Personas consideradas | 42 elegibles distintos propuestos; 108 nunca propuestos = 72 %. |
| Recomendaciones y carga | 20 responsabilidades independientes distribuidas entre 16 elegibles: una persona con 3, dos con 2 y trece con 1. Tres personas presentan alerta de acumulación. |
| Sin recomendación | 150 − 16 = 134 elegibles; 89,33 %. Esta cifra no es «sin cargo elegido». |

Construye registros consistentes que produzcan estas cifras; no escribas los valores en tarjetas. Separa fixtures de prueba de escenarios demo adicionales para no alterar accidentalmente las expectativas. Añade casos independientes para selección múltiple, primer anciano con responsabilidad vinculada y denominadores cero.

Los scripts de seed/reset deberán comprobar el identificador de demo, entorno y confirmación técnica apropiada. Un seed no crea personas ni procesos en Ozama. Incluye una prueba explícita del estado vacío de Ozama después de instalar.

## 23. Verificación y criterios de aceptación

Escribe pruebas que protejan invariantes reales y riesgos del dominio, no pruebas que repitan literalmente la implementación. Usa bases de datos reales en integración y navegadores reales en E2E. Un test con mocks de autorización no demuestra aislamiento entre iglesias.

Mantén una matriz `requisito → implementación → prueba → evidencia → estado`. Los siguientes criterios son obligatorios:

| ID | Escenario y condición de aprobación |
| --- | --- |
| AC-01 | Aprovisionar demo y Ozama crea bases y credenciales distintas; Ozama tiene cero datos operativos ficticios. |
| AC-02 | Un usuario A no accede a B alterando IDs, rutas, cabeceras, sesiones o cuerpos de API. |
| AC-03 | Las credenciales ordinarias de la base A no se conectan ni consultan B; conexiones, cachés y pools no cruzan contexto. |
| AC-04 | Fotos, objetos, reportes, colas, notificaciones, enlaces y canales en vivo mantienen el mismo aislamiento. |
| AC-05 | El administrador global administra operación, pero no descifra contenido E2EE ni obtiene claves al asignarse un rol. |
| AC-06 | Roles personalizados cumplen mínimo privilegio y no permiten escalada global; UI y API coinciden. |
| AC-07 | Bootstrap e invitaciones caducan; MFA protege privilegios y su recuperación no abre una puerta trasera de claves. |
| AC-08 | Importación valida y previsualiza; reintentar no duplica; homónimos permanecen distintos y nombres con tildes se encuentran correctamente. |
| AC-09 | No elegible aparece deshabilitado con motivo visible autorizado; nota privada no aparece en red, HTML o exportación de un usuario sin acceso. |
| AC-10 | Abrir propuestas lleva a todos los electores al mismo cargo y límite; un no elector no puede enviar. |
| AC-11 | Cinco participantes que proponen la misma persona producen un candidato con cinco proponentes, sin duplicados por texto o reintentos. |
| AC-12 | Un borrador no cuenta como respuesta; abstención sí completa el paso y no suma apoyo a candidatos. |
| AC-13 | El padrón congelado controla el 100 %; desconectarse o desactivar una cuenta no modifica retrospectivamente el denominador. |
| AC-14 | Depuración conserva decisiones y solo pasan a la boleta candidaturas confirmadas; cambios posteriores requieren una nueva versión/ronda. |
| AC-15 | Dos pestañas, doble toque y reintentos concurrentes producen una sola recepción efectiva por elector y ronda. |
| AC-16 | Carrera entre cierre y último envío, o doble cierre, tiene resultado transaccional único; el cliente conoce si fue recibido o rechazado. |
| AC-17 | Criptograma corrupto, candidato fuera de lista, selección excesiva o repetida, replay de otra ronda y abstención combinada se detectan sin confirmar un resultado inválido. |
| AC-18 | Cero votos, candidato único, empate, múltiples plazas y empate en último cupo tienen desenlaces explícitos y verificables. |
| AC-19 | Primer anciano deriva del grupo correspondiente y las responsabilidades vinculadas no inflan la carga independiente. |
| AC-20 | Abrir una ronda no expone conteos parciales de preferencias mediante UI, API, eventos, caché o logs. |
| AC-21 | Después de cerrar, escrutinios compatibles producen agregados verificables; discrepancias o claves ausentes impiden publicar resultados confirmados. |
| AC-22 | La junta ve participación y agregados según permisos, pero ningún reporte ordinario relaciona votante y elección. |
| AC-23 | Una recomendación no se etiqueta como elección congregacional; consentimiento, presentación, devolución y elección quedan diferenciados. |
| AC-24 | Una segunda responsabilidad genera alerta sin bloquear; dashboard lista cargos y usa denominadores verificables. |
| AC-25 | Las fórmulas del fixture de demo coinciden entre dashboard, reporte, exportación y organigrama; cero denominador se maneja correctamente. |
| AC-26 | Renombrar una persona/cargo o actualizar el catálogo no reescribe el historial ni informes ya emitidos. |
| AC-27 | PDF, Excel y CSV funcionan, respetan filtros/permisos, muestran ES/EN/FR y neutralizan fórmulas maliciosas. |
| AC-28 | Proponer y votar funciona en teléfono pequeño, teclado y lector de pantalla; foco, ampliación, contraste y errores se verifican manualmente. |
| AC-29 | Desconexión y reconexión conservan estado comprensible; nunca se afirma recepción sin acuse ni se sincroniza un voto fuera de fase. |
| AC-30 | Los tres idiomas cubren todo el producto, incluidos catálogo, errores, accesibilidad, invitaciones y documentos. |
| AC-31 | Un volcado del backend/objetos y sus secretos ordinarios no descifra categorías declaradas E2EE; la prueba identifica qué metadatos sí revela. |
| AC-32 | Alta/revocación de dispositivo, rotación, recuperación y pérdida definitiva de claves tienen pruebas y procedimientos reales. |
| AC-33 | Alterar, borrar, truncar, reordenar o restaurar una auditoría antigua se detecta frente a anclajes independientes. |
| AC-34 | Restaurar una copia de un tenant conserva coherencia e integridad y no afecta otro; se miden RPO/RTO. |
| AC-35 | Inventario de cargos y reglas coincide con fuentes aplicables; cada ficha y restricción tiene procedencia y estado de revisión. |
| AC-36 | Todas las acciones visibles están implementadas, persisten tras reinicio y no dependen de respuestas ficticias fuera de demo. |
| AC-37 | La carga documentada satisface objetivos o produce un informe explícito de desviaciones; no se publican cifras inventadas. |
| AC-38 | La entrega no contiene secretos, contraseñas universales, PII real en fixtures ni referencias a una aprobación institucional inexistente. |

Incluye pruebas unitarias de reglas y métricas; pruebas de integración de transacciones, aislamiento y permisos; pruebas E2E de flujos por rol/idioma; revisión visual de pantallas clave y documentos; evaluación de seguridad y recuperación. Una auditoría especializada de criptografía/seguridad deberá quedar identificada como realizada o pendiente, sin confundirla con tests automáticos.

## 24. Entregables y orden de implementación

Entrega el repositorio completo, ejecutable y documentado, no solo un plan. Organiza el trabajo en fases con demostraciones persistentes:

1. Fundamentos: inventario normativo, decisiones de producto, modelo de amenazas, arquitectura, modelo de datos y sistema de diseño.
2. Plataforma: aprovisionamiento, bases por tenant, autenticación, MFA, permisos, claves y auditoría.
3. Preparación: padrón cifrado, fotos, Excel, catálogos, junta, ciclos, vacantes y configuración.
4. Núcleo: propuestas, consolidación, depuración, votación, escrutinio, empates, consentimiento y cierre.
5. Resultados: dashboards, organigramas, reportes, elección congregacional registrada e historial.
6. Calidad integral: ES/EN/FR, móvil, accesibilidad, resiliencia, backups, carga, seguridad y revisión visual.
7. Entrega: demo navegable, Ozama vacío, bootstrap seguro, instalación reproducible y evidencia de aceptación.

No relegues cifrado, aislamiento o permisos al final: condicionan el modelo desde la primera fase. Las fases de diseño no justifican abandonar la implementación pedida. Si existe un impedimento externo, documenta exactamente qué queda pendiente, continúa lo independiente y no declares completo lo que no lo está.

Archivos y materiales mínimos de entrega:

- `README.md`: instalación, requisitos, comandos, configuración y recorrido por roles.
- `.env.example` sin secretos y procedimientos seguros de bootstrap.
- Migraciones, scripts de aprovisionamiento y seeds exclusivos de demo.
- `docs/architecture.md`, diagramas de componentes, modelo de datos y ADR.
- `docs/normative-matrix.md` o equivalente estructurado y catálogo versionado de cargos, funciones y fuentes.
- `docs/security.md`, `docs/threat-model.md`, `docs/encryption.md` y matriz ASVS.
- `docs/privacy.md`: clasificación, retención, destinatarios y aplicación territorial por validar.
- `docs/api` con contratos HTTP/eventos, errores e idempotencia.
- `docs/design-system.md`, glosario ES/EN/FR y evidencia de accesibilidad.
- `docs/dependencies.md`, licencias, SBOM y revisión de vulnerabilidades.
- `docs/operations.md`, backups/restauración, claves, incidentes, despliegue y costos estimados.
- Guía de administrador global, administrador de iglesia, secretario y miembro de junta.
- Suite de pruebas, matriz de aceptación, resultados y evidencia visual de móvil, escritorio y reportes.
- `docs/known-limitations.md` con estado real de verificaciones institucionales, legales, de seguridad y capacidades no completadas.

Al finalizar, informa qué funciona, cómo se ejecuta y se entra de forma segura, qué se verificó, los resultados de pruebas y las dependencias externas pendientes. Nunca afirmes «100 % seguro», «100 % conforme», «inmutable» o «listo para producción» únicamente porque la aplicación compila. Esas propiedades necesitan alcance definido, evidencia y revisión apropiada.

## 25. Instrucción final de ejecución

Construye esta solución con criterio profesional y termina cada flujo autorizado hasta su verificación. Conserva la claridad del producto para miembros que usarán principalmente su celular. Cada decisión técnica debe servir a la confianza, confidencialidad, orden institucional, facilidad de uso o mantenibilidad.

La meta de calidad es concreta: iglesias realmente aisladas; propuestas y votos íntegros; personas tratadas con respeto; resultados comprensibles; historial verificable; diseño accesible en tres idiomas; datos demo claramente separados; Iglesia Adventista Ozama preparada para iniciar con sus propios datos. Entrega evidencia de estas propiedades y una aplicación operativa que las materialice.
