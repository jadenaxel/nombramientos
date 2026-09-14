# Accesibilidad

Fecha de corte: **14 de septiembre de 2026**.

[WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/) es un objetivo de ingeniería, no una conformidad declarada. La automatización actual aporta evidencia útil pero no decide todos los criterios ni sustituye personas usuarias, lectores de pantalla y dispositivos físicos.

## Implementación local

- HTML semántico, landmarks, `main` y enlace de salto.
- Botones, enlaces, inputs, radios y checkboxes nativos/primitivos con nombres accesibles.
- Navegación adaptable con objetivos táctiles de al menos 44 px en recorridos probados.
- Reflujo a 320 CSS px en acceso, invitación, bootstrap de plataforma, preferencias y sesión/recibo cubiertos.
- Foco visible; dialogs/drawers con manejo de foco de sus primitivas.
- Acceso, aceptación de invitación, desbloqueo de llaves y bootstrap global usan validación localizada ES/EN/FR, resumen enfocable, `aria-invalid`/`aria-describedby` y no exponen el mensaje interno del servidor; conservan un identificador de correlación localizado cuando existe.
- Los formularios sensibles borran la contraseña tanto ante validación local como ante fallo del servidor.
- Estados de conectividad/recepción persistentes; el éxito no depende solo de un toast.
- Anuncios `aria-live` para cambios relevantes sin anunciar cada heartbeat.
- Preferencias persistentes de movimiento reducido, contraste y texto; atributos efectivos en `html`.
- PWA con allowlist de recursos públicos: no cachea navegaciones autenticadas, `/v1` ni `/api`.
- Rutas y `lang` para ES/EN/FR; fechas de tenant usan su zona IANA en superficies actualizadas.

La existencia de estos patrones no prueba su aplicación perfecta en todos los estados.

## Patrones obligatorios

- Un solo `h1` contextual y jerarquía coherente.
- Orden de tabulación lógico y foco nunca oculto por CTA fijo/safe area.
- Labels persistentes; placeholder no sustituye etiqueta.
- Error vinculado al campo y resumen enfocable cuando hay múltiples errores.
- Estado no comunicado solo por color/icono.
- Contador anunciado solo al cambiar por acción de la persona.
- Abstención semántica y mutuamente excluyente con candidaturas.
- Al llegar al máximo de selecciones, explicar/bloquear; nunca reemplazar silenciosamente una selección previa.
- Persona no elegible deshabilitada con motivo autorizado enlazado por `aria-describedby`.
- Recibo seleccionable, persistente y enfocado/anunciado después del commit.
- Nota restringida ausente del DOM/red cuando falta permiso; no basta CSS.
- Gráfico con título, denominador y tabla equivalente.
- Organigrama con lista jerárquica equivalente.
- Todas las acciones visibles deben estar autorizadas y producir resultado/error real.

## Idiomas

El locale de URL controla `html lang` y los recorridos cubiertos en español, inglés y francés. Códigos internos deben transformarse en etiquetas humanas localizadas; nombres propios e IDs no se traducen.

Queda pendiente:

- revisión lingüística institucional de los tres idiomas;
- inventario completo de texto directo/errores nuevos;
- expansión francesa y truncamiento en todos los viewports;
- traducciones oficiales del vocabulario denominacional.

## Documentos

- PDF local usa texto real, subconjuntos estáticos de Bitstream Vera Sans embebidos, wrapping, paginación y encabezados repetidos; el cierre final lo renderizó de forma independiente con Poppler.
- XLSX usa hoja/títulos/encabezados y celdas sin fórmulas.
- CSV es UTF-8 con BOM y encabezados localizados.

El PDF actual no es PDF/UA etiquetado. Falta validar orden de lectura, tags, tablas, idioma, marcadores y salida impresa con tecnologías de asistencia. XLSX/CSV tampoco son accesibles automáticamente por tener encabezados.

## Evidencia automatizada

La matriz configurada:

| Proyecto | Motor / viewport |
|---|---|
| `desktop-chromium-es` | Chromium 1440×900 |
| `desktop-firefox-en` | Firefox 1280×800; condicional al preflight nativo |
| `mobile-chromium-es` | Chromium táctil 412×915 |
| `mobile-webkit-fr` | WebKit táctil 390×844 |
| `mobile-small` | Chromium táctil 320×568 |

Pruebas existentes cubren, según el proyecto:

- locale/`lang`, acceso y redacción de errores;
- un recorrido básico de tabulación;
- reflujo, overflow horizontal y objetivos táctiles;
- preferencias de accesibilidad y cache PWA;
- propuesta/recibo con offline/online;
- MFA, invitación localizada, ciclo/desbloqueo de claves y ceremonia de custodia;
- axe sin descartar impactos moderados o menores y con tags exactos `wcag2a`, `wcag2aa`, `wcag21aa` y `wcag22aa` en superficies críticas.

El pase integral actual ejecutado entre `2026-09-14T10:56:10.4065404Z` y `2026-09-14T11:04:21.4060919Z` aprobó 25 etapas y aceptó únicamente la sonda opcional de Firefox; completó 1.196/1.196 pruebas no Playwright. La matriz Playwright planificó 160 casos: 106 aprobaron, 54 fueron exclusiones exactas de la allowlist y ninguno falló. Chromium de escritorio aprobó 40/40; Chromium móvil, Chromium a 320 px y WebKit móvil aprobaron 22 y excluyeron los mismos 18 casos mutables permitidos en cada proyecto. Chromium y WebKit fueron obligatorios. La política de skips coincidió exactamente, sin entradas inesperadas o ausentes. Los cuatro perfiles activos comprobaron además que entrar por la IP de loopback termina en el origen WebAuthn canónico sin perder estado de navegación.

Una inspección CUA suplementaria —no una auditoría humana de conformidad— recorrió acceso, invitación y bootstrap de plataforma en ES/EN/FR a 320×700. La tabulación alcanzó enlace de salto, selectores de locale, campos, botón e invitación, con outline calculado sólido de 2,4 px. Un acceso francés inválido conservó la ruta localizada, mostró el error de correlación localizado, borró la contraseña y no produjo loop de redirección. Los tres manifiestos localizados respondieron 200 con el MIME y metadatos esperados. La inspección detectó inicialmente overflow horizontal real en el bootstrap de los tres idiomas; se corrigió y la revalidación del build local de producción dejó `scrollWidth=305` dentro del viewport, inputs habilitados tras hidratación y botones de 48–56 px de alto. Una regresión automatizada adicional fija 320×720 y exige ausencia de overflow para ES/EN/FR. Tras el cierre actual se volvió a inspeccionar visualmente el acceso canónico `localhost`: la ruta segura mostró passkey primero, ayuda específica para el mismo teléfono, alternativa de contraseña y foco/labels accesibles, sin introducir credenciales ni secretos.

Algunas mutaciones corren solo en `desktop-chromium-es` para no alterar el fixture cinco veces. En este host, Firefox no supera el preflight nativo con `WINDOWS_NATIVE_SPAWN_UNKNOWN`; por eso la etapa quedó `accepted-optional` y no se atribuye cobertura a ese motor. Playwright WebKit ayuda a detectar incompatibilidades, pero no sustituye Safari/iOS físico. Los resultados exactos están en [verification.md](verification.md).

## Matriz manual bloqueante

Antes de producción se requiere evidencia humana fechada de:

- solo teclado en todos los recorridos y estados de error/vacío;
- NVDA + Chrome y Edge;
- VoiceOver + Safari en macOS/iOS;
- TalkBack + Chrome en Android;
- zoom 200 % y 400 %, texto del sistema ampliado;
- 320×568, 390×844, 412×915, 1280×800 y 1440×900;
- vertical/horizontal, una mano, touch y puntero;
- movimiento reducido, alto contraste/contraste reforzado;
- pérdida/reconexión sin pérdida de foco ni falso éxito;
- generación, descarga e impresión de documentos;
- nombres largos, homónimos, francés expandido y denominador cero.

Registrar dispositivo, OS, navegador/AT y versiones, locale, pasos, evidencia, severidad, corrección y re-test.

## Criterios de aceptación

1. Proponer y votar se completa a 320 px sin scroll horizontal.
2. Cargo, límite, selección, abstención, confirmación y recibo se entienden con lector.
3. El foco no queda detrás del CTA ni salta por actualizaciones SSE.
4. Cada error explica qué ocurrió y cómo continuar.
5. Gráficos/organigrama tienen alternativa equivalente.
6. ES/EN/FR no mezclan idiomas ni truncan controles.
7. Zoom/texto ampliado no pierde contenido o acción.
8. Ningún resultado se afirma por color, animación o toast únicamente.

Hasta completar la matriz manual, la formulación correcta es “controles y pruebas automáticas de accesibilidad implementados”, no “WCAG 2.2 AA conforme”.
