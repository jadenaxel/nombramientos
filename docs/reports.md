# Centro de reportes

Fecha de corte: **13 de septiembre de 2026**.

## Modelo implementado

Un navegador autorizado solicita una instantánea proyectada por tipo/audiencia, descifra únicamente los campos permitidos, compone PDF/XLSX/CSV y cifra el artefacto antes de persistirlo. El servidor conserva metadatos, manifiesto, hashes y ciphertext; no necesita recibir el archivo final en claro.

Cada emisión usa un ciclo durable:

1. crear solicitud `pending` con tipo, audiencia, locale, formato, filtros e idempotencia;
2. obtener una instantánea autorizada y calcular `snapshotSha256`;
3. generar el archivo localmente;
4. cifrar con AES-GCM y AAD exacto ligado a tenant/reporte/versión/tipo/audiencia/locale/formato/nombre/hash;
5. completar como `ready`, o marcar `failed` con código estable;
6. al descargar/imprimir desde historial, validar manifiesto/hashes/tamaños/contexto antes de descifrar;
7. auditar emisión, descarga e impresión sin almacenar el plaintext.

La migración defensiva marca `expired` cualquier fila heredada sin artefacto cifrado; no se presenta como descargable. Esta regla no justifica datos de ejemplo en un tenant real: Ozama debe mantener también `report_versions` en cero hasta su activación.

## Catálogo

| Tipo API | Informe | Audiencias permitidas | Permisos de datos |
|---|---|---|---|
| `cycle_summary` | Resumen operativo verificable | comité, auditor, iglesia | `aggregate.read` |
| `general_recommendations` | Recomendaciones generales | comité, auditor, iglesia | `aggregate.read` + `organigram.read` |
| `elected_board` | Directiva elegida | comité, auditor, iglesia | `aggregate.read` + `organigram.read` |
| `department` | Estado por departamento | comité, auditor, iglesia | `aggregate.read` + `organigram.read` |
| `office_round` | Cargo y ronda | comité, auditor | `aggregate.read` |
| `committee_participation` | Participación nominal | comité, auditor | `member.read` + `participation.nominal.read` |
| `responsibility_distribution` | Distribución de responsabilidades | comité, auditor | `aggregate.read` + `organigram.read` |
| `unconsidered_unassigned` | Elegibles no considerados/sin cargo | comité, auditor | `member.read` + `aggregate.read` + `organigram.read` |
| `progress` | Avance | comité, auditor, iglesia | `aggregate.read` + `organigram.read` |
| `session_minutes` | Acta de sesión | comité, auditor, iglesia | `aggregate.read` |
| `cycle_history` | Historial de ciclos/mandatos | comité, auditor, iglesia | `aggregate.read` |
| `audit_integrity` | Auditoría e integridad | comité, auditor | `audit.read` |
| `roster_import_incidents` | Padrón e incidencias de importación | comité | `member.read` + `member.import` |

Además de los permisos de datos, leer metadatos exige `report.read` y emitir/descargar exige `report.export` según la ruta. La API recalcula acceso por par exacto tipo/audiencia; ocultar una opción en UI no es el control de seguridad.

El acceso desde el organigrama normaliza el alias de navegación `department_organization` al tipo canónico `department`, conserva `cycleId`/`departmentId` por ID estable y traduce `organizationStage` al filtro persistido `assignmentState`. La etapa no se infiere del nombre visible: `proposal` y `elected` se proyectan por separado.

## Proyección y privacidad

- El endpoint de instantánea acepta un `cycleId` explícito o resuelve el ciclo activo/más reciente.
- Solo devuelve conjuntos necesarios para el tipo solicitado. Las proyecciones aplican allowlists; no basta ocultar una columna en el cliente.
- La audiencia iglesia excluye candidaturas internas, razones/notas, participación nominal, actores y conteos internos no publicados.
- Actas para iglesia eliminan snapshots de miembro; conservan solo estado público de asignación y sesión.
- Participación nominal solo aparece para tipo, audiencia y permiso explícitos.
- Auditoría e importaciones no dependen de `aggregate.read`; un usuario autorizado a esos informes no queda bloqueado por una consulta de dashboard ajena.
- Los filtros visibles se limitan a los que el tipo realmente consume. Cambiar de tipo limpia filtros anteriores para evitar persistencia engañosa.
- Fechas se formatean con la zona IANA del tenant, no con la zona del navegador.
- La proyección de organigrama usa IDs estables de ciclo/departamento. En etapa `elected` solo incluye elecciones; en etapa `proposal` conserva recomendación/aceptación como preliminares y nunca las relabela como elección.
- La audiencia iglesia no recibe la proyección preliminar interna del organigrama. En la vista elegida, las plazas todavía no elegidas aparecen como vacantes sin identidad ni sobres privados.
- La carga de responsabilidades agrupa por `memberId`, cuenta solo asignaciones `independent=true` y presenta las designaciones vinculadas como funciones nominales separadas.

La exactitud histórica de métricas y organigrama se apoya en snapshots congelados de ciclo/asignación: perfil, foto, cargo y departamento no se resuelven desde el registro maestro actual. Las pruebas de base y semántica ejercitan selección de ciclo anterior, separación de etapa y ausencia de mezcla con el ciclo activo. El real-stack autorizado aprobó 3/3 contra API/PostgreSQL efímeros reales y el pase integral posterior confirmó el build y esas suites; cleanup, catálogo y huellas protegidas quedaron íntegros.

## Formatos

- **PDF:** A4, subconjuntos estáticos de Bitstream Vera Sans embebidos, wrapping, paginación, encabezado repetido, audiencia, huella e indicador de página. No es PDF/UA etiquetado.
- **XLSX:** título/metadatos, encabezados, anchos, panel congelado y celdas sin fórmulas ejecutables.
- **CSV:** UTF-8 con BOM, quoting y neutralización de valores que comienzan por `=`, `+`, `-` o `@`.
- **Impresión:** solo PDF ya verificado y descifrado localmente; se registra el evento antes de abrir la vista de impresión.

El cierre local renderiza el PDF exportado con Poppler (`pdftoppm`) y falla ante errores del renderer o diagnósticos de sintaxis/fuentes. Esta comprobación de interoperabilidad no convierte el documento en PDF/UA ni sustituye tecnologías de asistencia.

La memoria que contiene bytes claros se rellena con cero al terminar en los caminos controlados. JavaScript y el navegador no ofrecen una garantía forense de borrado físico.

## Integridad

Antes de usar un artefacto histórico, el cliente coteja:

- tenant, report ID y request version;
- tipo, audiencia, locale, formato, nombre y media type;
- `snapshotSha256`, `artifactSha256`, `ciphertextSha256`;
- bytes claros/cifrados y tag AES-GCM;
- AAD exacto y key ID/generación.

Un mismatch falla cerrado. Si el artefacto pertenece a una generación histórica de clave, la UI guía a seleccionar esa generación; no intenta descifrar con contexto aproximado.

Los hashes detectan inconsistencia dentro del modelo; no son firma institucional ni prueban por sí solos que el software servido al navegador era confiable.

## Evidencia

Pruebas unitarias, API y de base comprueban:

- los 12 informes institucionales más `cycle_summary`;
- audiencias y permisos exactos;
- restricción por scope al listar/leer un ID;
- transición `pending/ready/failed/expired`;
- AAD, hashes, tamaños, manifest y tamper rejection;
- neutralización de fórmulas y formato PDF/XLSX/CSV;
- redacciones de audiencia y snapshots de acta;
- filtros condicionales y zona horaria.
- filtros por IDs estables, proyección `proposal`/`elected`, snapshots históricos y exclusión de funciones vinculadas del conteo independiente.

`apps/web/lib/report-export.ts` es el generador puro compartido por la UI y `real-stack-closure.spec.ts`; `real-stack-e2e-wiring.test.ts` impide volver a separarlos o mockear el flujo dedicado. Playwright conserva un ejemplo analizado de los tres formatos en ES/EN/FR y prueba descarga desde historial. Ese recorrido ordinario instala rutas de reporte aisladas: demuestra la generación y validación del artefacto en el cliente, pero no demuestra por sí solo persistencia real en API/PostgreSQL. La ejecución dedicada y expresamente autorizada sí comprobó solicitud, generación, cifrado, persistencia, lectura, descarga y auditoría reales, junto con importación y ceremonia de boleta/escrutinio, y aprobó 3/3; la evidencia sanitizada está en [`artifacts/real-browser-stack-local.json`](../artifacts/real-browser-stack-local.json). Esto cierra el alcance técnico local de AC-27, no la matriz semántica humana completa ni PDF/UA.

La evidencia vigente `demo-cycle-summary` fue inspeccionada adicionalmente: el PDF A4 de una página renderizó con Poppler, usa fuentes Bitstream Vera TrueType embebidas mediante `/FontFile2`, incluye mapas `/ToUnicode` y operadores visibles `Tj`, y no mostró clipping ni solapamientos; el inspector rechaza `FontFile3`/WOFF2. El XLSX contiene una hoja `Report`, rango usado `A1:B13`, tabla, filtro y panel congelado, con valores 40/20/15/10 y sin errores de fórmula; el CSV contiene BOM UTF-8 y 13 líneas localizadas. Es una inspección local del artefacto generado, no una evaluación PDF/UA, de lector de pantalla ni una matriz semántica de los trece tipos.

También se añadió un recorrido de organigrama con selección de ciclo/etapa, filtros, zoom, vista móvil y deep-link de reporte; el pase global posterior a la integración está registrado en [verification.md](verification.md).

## Pendiente externo o manual

- revisión institucional del contenido y vocabulario de cada informe;
- evaluación semántica/manual exhaustiva para todos los tipos/filtros/audiencias/locales;
- PDF etiquetado y prueba con tecnologías de asistencia;
- límites y paginación sobre volúmenes productivos;
- política legal de retención/expiración/descarga;
- firma institucional, sello de tiempo y WORM, si fueran requisitos;
- auditoría criptográfica y pentest del flujo de artefactos.
