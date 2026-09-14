# Sistema de diseño

## Dirección

La interfaz debe sentirse institucional, serena y precisa. “Premium” se expresa mediante jerarquía, espacio, tipografía, estados terminados y respuesta rápida; no mediante decoración, animación abundante o cifras ficticias.

## Identidad adventista

Fuentes oficiales consultadas el 11 de septiembre de 2026:

- [Sistema de identidad](https://www.adventist.design/), versión visible 2.1.0.
- [Símbolo](https://www.adventist.design/global-elements/the-church-symbol/).
- [Creation Grid](https://www.adventist.design/global-elements/the-creation-grid/).
- [Color](https://www.adventist.design/global-elements/color/).
- [Advent Sans](https://www.adventist.design/global-elements/advent-sans/).
- [Toolkit y descargas](https://www.adventist.design/downloads/toolkit/).

La guía indica que no existe un color global oficial. La paleta siguiente es una dirección de producto pendiente de confirmación regional/local; no debe llamarse “paleta oficial”.

Usar exclusivamente SVG oficiales ES/EN/FR y preservar proporción, color sólido y espacio de protección. No redibujar el símbolo ni usarlo como adorno repetitivo. No sugerir patrocinio o certificación inexistente.

Advent Sans se reserva para identificadores institucionales cuando los archivos, licencia y autorización de marca hayan sido verificados. La propia guía recomienda Noto Sans como tipografía secundaria; por ello Noto Sans variable se sirve localmente como fuente de interfaz y texto continuo, con licencia OFL conservada en `apps/web/vendor`. Cualquier fallback conserva tildes y glifos ES/EN/FR.

La Creation Grid puede inspirar acceso, onboarding y portadas: seis columnas de contenido y una séptima columna diferenciada sin texto, salvo el símbolo permitido. Las pantallas operativas usan la cuadrícula funcional que mejor preserve la tarea; no se fuerza el motivo sobre una boleta móvil.

## Tokens de color candidatos

```text
canvas                 #F5F7FA
surface                #FFFFFF
surface-subtle         #EDF2F6
text-strong            #172337
text-default           #34465C
text-muted             #566579
border                 #D8E0E8
action-primary         #124E78
action-primary-hover   #0D3D5F
accent                 #0F766E
status-success         #176B43
status-warning         #8A5A00
status-danger          #B42318
status-information     #1D5FA7
focus                  #6D28D9
```

Son candidatos, no evidencia de contraste. Antes de congelarlos se prueban combinaciones reales para WCAG 2.2 AA. Ningún estado depende solo de color: siempre incluye texto y, cuando ayude, icono.

## Tipografía

| Uso | Fuente | Tamaño/altura orientativos |
|---|---|---|
| Identificador institucional | Advent Sans aprobada | según lockup oficial |
| Título de página | Noto Sans 650–700 | 28/36 escritorio, 24/32 móvil |
| Título de sección | Noto Sans 600–700 | 20/28 |
| Cuerpo | Noto Sans 400 | 16/24 |
| Ayuda/metadato | Noto Sans 400–500 | 14/20; nunca menor para contenido esencial |
| Métrica | Noto Sans, números tabulares | 28–40 con denominador cercano |

Longitud ideal de texto continuo: 45–75 caracteres. No usar mayúsculas sostenidas en párrafos ni letter-spacing que perjudique Advent Sans.

## Espaciado y forma

- Base: 4 px.
- Espacios: 4, 8, 12, 16, 24, 32, 48 y 64 px.
- Control móvil: 48 px de alto como meta del producto; escritorio 40–44 px.
- Radios: 8 px en controles, 12 px en cards, 16 px en paneles destacados.
- Bordes sutiles; sombra solo para jerarquía flotante.
- Contenido principal hasta 1440 px; texto hasta 72 caracteres por línea.
- Rail de escritorio 256–272 px; navegación inferior móvil con máximo cuatro destinos principales.

## Estados semánticos

| Familia | Uso |
|---|---|
| Neutral | pendiente, borrador, no aplica |
| Información | fase activa, sincronización, acción de trabajo |
| Advertencia | pausa, ausencia, vencimiento próximo, empate |
| Peligro | error, anulación, discrepancia, clave ausente |
| Éxito técnico | guardado/recepción confirmados |
| Resultado interno | color informativo propio; nunca el verde de “elegida” |
| Elegida/vigente | éxito institucional, solo después del acto correspondiente |

No usar “ganador” ni “elegido” para un resultado interno. Diferenciar visualmente `resultado interno → recomendación → presentada → elegida → vigente`.

## Componentes

- `AppShell`, `TenantContextBar`, `CycleContextBar`, `DemoBadge`, `AudienceBadge`.
- `PhaseStepper`, `AssignmentStatusRail`, `PreflightChecklist`.
- `CandidateCard`, `CandidatePicker`, `SelectionTray`, `StickyActionBar`.
- `ParticipationProgress`, `ConnectionBanner`, `StaleDataCallout`, `ReceiptCard`.
- `GuardedAction`, `ConfirmDialog`, `RestrictedContentPanel`.
- `MetricCard` con período, fase, denominador, versión y hora.
- `AccessibleDataTable` con representación móvil en lista.
- `OrgTree` y `OrgList` equivalentes.
- `ImportWizard`, `ReportPreview`, `IntegrityStatus`.
- `EmptyState`, `ErrorSummary`, `Skeleton` sin datos ficticios.

## Layouts críticos

### Miembro en móvil

1. Iglesia, cargo, fase y conexión.
2. Instrucción y acceso discreto a la ficha del cargo.
3. Búsqueda/lista de candidatos.
4. Selección persistente y contador.
5. CTA fijo que respeta teclado y safe area.
6. Confirmación.
7. Recibo persistente sin contenido del voto.

### Conducción en escritorio

- Encabezado con ciclo/cargo/fase.
- Área principal de tarea y precondiciones.
- Participación `recibidos / padrón congelado`.
- Pendientes nominales solo con permiso.
- Acciones de fase separadas de navegación.
- Ningún agregado de preferencia durante ronda abierta.

### Ozama vacío

Checklist de configuración con valores reales en cero. No hay fotografías, personas, ciclos, votos ni métricas de ejemplo. Cada CTA aparece únicamente a quien tenga permiso.

## Responsive

- 320–479 px: una columna, cards, filtros en sheet, CTA fijo.
- 480–767 px: una o dos columnas según contenido.
- 768–1023 px: rail colapsable y tablas simplificadas.
- 1024 px+: navegación lateral, contexto superior y grids de análisis.
- Organigrama móvil inicia en lista jerárquica; el lienzo es opcional.
- Tablas se transforman en listas semánticas, no miniaturas ilegibles.

## Movimiento e iconos

- Transiciones funcionales de 120–200 ms.
- Respetar `prefers-reduced-motion`.
- Sin confeti, parallax o animación en métricas.
- Iconos de una sola familia y trazo coherente; no usar símbolos religiosos como decoración.

## Gráficos

- Barras, progreso y distribuciones simples.
- Etiquetas directas y tabla equivalente.
- Sin 3D, arcoíris ni animaciones ornamentales.
- Advertir cuando una selección múltiple permite porcentajes acumulados mayores a 100 %.
- “No aplica” ante denominador cero.

## Temas y preferencias

La aplicación persiste localmente preferencias no sensibles de tamaño de texto, contraste reforzado, reducción de movimiento y densidad. Incluye restablecimiento explícito y respeta la preferencia de movimiento del sistema. El tema claro es el único validado; el modo oscuro no se expone hasta verificar cada combinación. Los documentos impresos conservan un tema claro específico.

## Validaciones pendientes

- Aprobación de identidad y uso de marca por autoridad competente.
- Confirmación de paleta regional para Ozama.
- Autorización final para cualquier uso futuro de Advent Sans; Noto Sans/OFL ya está inventariada.
- Pruebas de contraste de componentes reales.
- Revisión visual ES/EN/FR, nombres largos, 320 px y documentos multipágina.
