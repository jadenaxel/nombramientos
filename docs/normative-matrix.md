# Matriz normativa

Fuente ejecutable: `packages/catalog/src/normative-matrix.v2025-1.ts`.

## Paquete

- Revisión canónica de contenido: `2025.1.0`
- Estado del paquete: `draft`; la revisión es estable en código, pero no está validada para el tenant Ozama ni aprobada por su autoridad territorial.
- Revalidación de fuente oficial: **13 de septiembre de 2026**. El portal de la Asociación General seguía publicando el Manual de Iglesia y la comunicación oficial consultada seguía identificando la edición 21.ª de 2025 como la más reciente disponible. Esta comprobación no resuelve la jurisdicción ni los suplementos aplicables a Ozama.
- Fuente primaria cotejada: *Seventh-day Adventist Church Manual*, 21.ª edición, revisada en 2025, inglés.
- [Portal oficial](https://gc.adventist.org/church-manual/).
- [PDF oficial consultado](https://gc.adventist.org/wp-content/uploads/2025/10/Seventh-day_Adventist_Church_Manual-2025-10-13.pdf), 248 páginas en el archivo verificado.
- Fuente de apoyo: *Seventh-day Adventist Elder's Handbook*, revisión 2016. No reemplaza el Manual vigente.

Los números indicados son páginas impresas. En el PDF consultado coinciden con la numeración humana del documento, pero deben volver a cotejarse al cambiar el archivo fuente.

El mapeo de capítulos comprobado y protegido por regresión es: pp. 80–119, `Chapter 9 — Local Church Officers and Organizations`; pp. 120–125, `Chapter 10 — Elections`; p. 190, `Chapter 9 Notes`; y pp. 191–192, `Chapter 10 Notes`, tópico `1. Sample List of Church Leaders (see p. 122).`.

## Reglas registradas

| ID | Clasificación | Regla resumida | Sección/página | Estado de implementación |
|---|---|---|---|---|
| NM-001 | `norma_manual` | La comisión prepara/recomienda; la iglesia elige | Chapter 10, How the Process Works, p. 121 | `verified_with_evidence`: resultado interno, consentimiento, recomendación, presentación, devolución, elección y vigencia no se intercambian |
| NM-002 | `norma_manual` | Pastor y asistentes son designados por la autoridad territorial, no vacantes de la comisión | Chapter 10, Work of the Nominating Committee, p. 122 | `verified_with_evidence`: el motor bloquea vacantes para `conference_appointment`, `ex_officio` y configuración local no validada |
| NM-003 | `norma_manual` | Debe obtenerse consentimiento para servir | Chapter 10, Consent of Prospective Officers, pp. 122–123 | `verified_with_evidence`: consentimiento/aceptación/rechazo versionados |
| NM-004 | `norma_manual` | Consultas y deliberaciones son confidenciales | Chapter 10, Discussions Are Confidential, p. 123 | `verified_with_evidence`: separación nominal/preferencia, redacciones, audiencias y E2EE; la revisión independiente externa sigue pendiente |
| NM-005 | `norma_manual` | El informe se presenta a la iglesia, no a la junta como sustituto | Chapter 10, Reporting to the Church, p. 123 | `verified_with_evidence`: presentación y devolución diferenciadas, versionadas y auditadas |
| NM-006 | `norma_manual` | La elección congregacional indicada usa mayoría de presentes y votantes | Chapter 10, Reporting to the Church, p. 123 | `verified_with_evidence`: decisión congregacional separada del agregado interno; acta/contexto requerido |
| NM-007 | `norma_manual` | Primer anciano se designa dentro del grupo de ancianos | Chapter 9, First Elder, p. 84 | `verified_with_evidence`: `linked_designation` exige una asignación base válida del mismo mandato, conserva vínculo/evidencia auditada, impide una ronda electoral directa y no duplica carga independiente |
| NM-008 | `norma_manual` | Docentes de Escuela Sabática siguen recomendación del consejo y aprobación de junta | Chapter 10, Work of the Nominating Committee, p. 122 | `verified_with_evidence`: motor, API y UI bloquean propuestas/papeletas ordinarias y preservan el cargo como procedimiento separado; la vía positiva requiere validación denominacional |
| NM-009 | `norma_manual` | La estructura puede variar según tamaño/necesidad | Chapter 10, Work of the Nominating Committee, p. 122 | `verified_with_evidence`: aplicabilidad por ciclo versionada, reversible y auditada; Ozama debe aprobar qué estructuras aplican |
| NM-010 | `norma_manual` | Vacante durante el mandato exige nuevo procedimiento y elección | Chapter 10, Filling Vacancies Between Elections, p. 124 | `verified_with_evidence`: un retiro/finalización crea un proceso sustituto enlazado sin reescribir la asignación anterior |
| PV-001 | `configuracion_producto` | Una ronda activa por ciclo | Sin atribución normativa | `verified_with_evidence`: guard de unicidad y flujo cubiertos por pruebas |
| PV-002 | `configuracion_producto` | No publicar resultados parciales | Decisión de confidencialidad del producto | `verified_with_evidence`: contrato de publicación y audiencias cubierto por pruebas |
| PEND-001 | `pendiente_validacion` | Jurisdicción regional de Ozama desconocida | Sin fuente todavía | `blocked_pending_validation` |

## Regla sensible de elegibilidad

El pasaje *Work of the Nominating Committee* de la página 122 contiene condiciones de membresía y mayordomía. Implementarlas exige:

1. interpretación de la autoridad eclesiástica aplicable;
2. proceso humano que preserve confidencialidad;
3. minimización de datos financieros;
4. prohibición de importar historiales de aportes al producto;
5. definición de motivo visible y nota restringida;
6. prueba de que un usuario sin permiso no recibe el dato por red, HTML, búsqueda o exportación.

Hasta completar esas validaciones, el catálogo no debe inferir elegibilidad desde finanzas ni presentar una preferencia local como regla universal.

En la implementación actual, cambiar la elegibilidad de una persona afectada pausa el proceso sin reescribir padrón, candidaturas, respuestas, votos ni denominadores congelados. La resolución requiere versión, conjunto exacto de pausas, código de razón y evidencia cifrada: una ronda abierta se anula/reemplaza si ya aceptó respuestas; una asignación solo permite rechazo, retiro, devolución o sustitución antes de cerrar el proceso fuente. Estas son salvaguardas de integridad del producto y **no** sustituyen la validación denominacional del criterio de elegibilidad ni del procedimiento local.

## Inventario de cargos

`packages/catalog` contiene 67 cargos, 134 responsabilidades localizadas y 38 relaciones `reportsTo`: 64 cargos están `verified_primary_source`; `head_deaconess` y `assistant_church_clerk` siguen `pending_primary_source_validation`; y `adventist_men_leader` sigue `pending_regional_validation`. La numeración de capítulos y notas ya fue cotejada y tiene prueba de regresión. Cualquier elemento `pending_local_approval` no debe activarse por defecto.

## Validaciones pendientes

- Asociación/misión, unión y división de Ozama.
- Suplementos regionales vigentes y autoridad relativa.
- Traducciones oficiales disponibles y permiso de redistribución.
- Títulos exactos de cargos auxiliares, juveniles, musicales y estructuras opcionales.
- Procedimiento local de consulta, presentación, objeción y vacantes.
- Autoridad, formato y evidencia de la vía positiva consejo→junta para los mecanismos separados.
- Selección autorizada de estructuras aplicables al ciclo de Ozama.
- Tratamiento local de pausas por elegibilidad, sustituciones y designaciones vinculadas, incluida la autoridad que aprueba cada resolución.
- Revisión del catálogo por responsables eclesiásticos antes de cambiar su estado a `tenant_validated`.
