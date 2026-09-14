# Rendimiento local — AC-37

Fecha de ejecución: **13 de septiembre de 2026**.

La evidencia de servidor autoritativa es [`artifacts/performance-scale-local.json`](../artifacts/performance-scale-local.json), esquema 3. La evidencia complementaria de navegador es [`artifacts/performance-browser-local.json`](../artifacts/performance-browser-local.json), esquema 2. Ambos archivos están sanitizados: no contienen contraseñas, tokens, URLs de conexión ni IDs operativos.

## Resultado

`overallPass: true`, desde `2026-09-13T03:16:20.875Z` hasta `2026-09-13T03:16:45.510Z`: **24,635 segundos** de pared según el propio artefacto.

| Presupuesto local | Carga real | Resultado | Umbral | Estado |
|---|---:|---:|---:|---|
| Acuse de mutación | 500 POST concurrentes | p95 1.288,811 ms | < 1.500 ms | Cumplido |
| Propagación | 500 eventos sobre 10 streams SSE | p95 990,481 ms | < 2.000 ms | Cumplido |
| Lectura representativa | 1.000 GET bajo 500 sesiones | p95 866,517 ms | < 2.000 ms | Cumplido |
| Padrón de 10.000 | 500 listados dentro del lote anterior | p95 714,602 ms | incluido en el presupuesto exclusivo de lectura | Cumplido |
| Fallos inesperados | todas las fases | 0 | 0 | Cumplido |

Las cifras usan coma decimal en este documento; el JSON conserva números con punto.

## Navegador con 10.000 miembros

El ensayo Chromium separado registró `overallPass: true` sobre 10.000 sobres AES-256-GCM sintéticos, generados únicamente en memoria, y 4.547.671 bytes por HTTP loopback:

| Operación de navegador | Resultado local |
|---|---:|
| Descarga | 12,9 ms |
| Parse | 8,3 ms |
| Descifrado | 128,9 ms |
| Índice de búsqueda | 19,3 ms |
| Pipeline descarga/descifrado/índice | 322,7 ms |
| Búsqueda p95 / máxima | 4,0 / 4,5 ms |
| Brecha máxima de frame con Web Worker | 16,7 ms |
| LCP / CLS / INP de laboratorio móvil | 160 ms / 0 / 16 ms |

La transferencia binaria y el trabajo fuera del hilo principal prueban exclusivamente el pipeline sintético standalone. El artefacto declara `productionMembersRouteMeasured: false`: no ejercita la ruta ni los componentes reales de Members, no llama a la API operativa, no consulta PostgreSQL y no usa credenciales o datos protegidos. LCP/CLS/INP corresponden a la página pública no autenticada `/es/auth/sign-in`. Es una medición de laboratorio en el equipo descrito, no un percentil de campo.

Los umbrales del artefacto browser son inclusivos (`≤ 300 ms` para p95/máximo de búsqueda, `≤ 250 ms` para brecha de frame, `≤ 2.500 ms` LCP, `≤ 200 ms` INP y `≤ 0,1` CLS). Esto contrasta deliberadamente con los presupuestos exclusivos (`<`) del runner de escala.

## Dataset y topología

- 10 tenants efímeros aislados;
- 50 participantes autenticados por tenant;
- 500 sesiones;
- 10.000 miembros por tenant, 100.000 total;
- una ronda de propuesta por tenant;
- 500 mutaciones HTTP reales;
- 1.000 lecturas HTTP reales, dos por participante;
- 10 streams SSE reales, uno por tenant.

El setup insertó 100.000 miembros dentro de una fase total de 11.577,796 ms, equivalente a 8.637,222 filas/s en ese equipo.

Para conservar el rate limiter por IP, el runner usó diez listeners Fastify en loopback que comparten el clúster PostgreSQL y un plano de control efímero del run. Esta topología no es un proxy/balanceador productivo.

## Ambiente registrado

| Componente | Valor |
|---|---|
| CPU | 12th Gen Intel Core i9-12900H, 20 CPU lógicas |
| Memoria | 15,736 GiB |
| Sistema | Windows `10.0.26200`, x64 |
| Node | v24.19.0 |
| V8 | 13.6.233.17-node.51 |
| Fastify | 5.12.1 |
| PostgreSQL | 18.6 |
| Transporte | HTTP/SSE sobre TCP loopback, sin TLS ni proxy |

## Integridad

Después de 500 mutaciones se verificó:

- 500 electores, 500 submissions y 500 recibos;
- 500 registros de idempotencia;
- 500 eventos de auditoría y 500 de outbox;
- cardinalidad y hashes distintos esperados por elector;
- 500 respuestas HTTP `201`, sin fallos de validación.

SSE observó los 500 eventos esperados y cada tenant coincidió con sus 50 eventos persistidos.

Las 1.000 lecturas devolvieron HTTP `200`, sin fallos de validación. El runner comprobó que el estado de negocio tenant no cambió durante la fase de lectura.

## Aislamiento y cleanup

- 10/10 credenciales runtime conectadas contra la base vecina recibieron SQLSTATE `42501`;
- 10/10 intentos HTTP con tenant ID foráneo fueron denegados;
- 10/10 rondas foráneas se ocultaron;
- cleanup dejó 0 bases, 0 roles y 0 filas de control efímeras;
- las huellas completas del plano de control, Demo y Ozama fueron idénticas antes y después; la del control fue
  `sha256:71ebf60379863c758405548af410982b9c2ca7bb3bb7d39fabede41763f9dc08`;
- el inventario global del clúster permaneció idéntico y no quedaron bases ni roles efímeros huérfanos;
- el runner declara `protectedOperationalTenantsTouched: 0`.

El entorno de carga es run-scoped. No se usaron Demo u Ozama para crear volumen.

## Cómo reproducir

Con PostgreSQL local instalado y el workspace compilable:

```powershell
pnpm --filter @nombramientos/api performance:scale:self-check
pnpm performance:scale:local
pnpm performance:browser:local
```

El runner rechaza PostgreSQL no-loopback, el puerto `5432`, una URL administrativa cuyo destino no sea la base `postgres` y nombres de cleanup que no coincidan exactamente con los generados.

La prueba modifica [`artifacts/performance-scale-local.json`](../artifacts/performance-scale-local.json). No comparar ejecuciones sin conservar hardware, versiones, topología, dataset, hora y ruido concurrente.

## Qué no mide

- TLS, proxy, WAN, jitter, pérdida o reconexión móvil real;
- un endpoint público único, balanceador o múltiples instancias;
- réplica, failover, backups concurrentes o observabilidad productiva;
- RUM/field Core Web Vitals; el LCP, CLS e INP registrados son una sola ejecución de laboratorio;
- consumo de memoria o energía y comportamiento en hardware móvil físico;
- hardware móvil, redes lentas o tecnologías de asistencia;
- generación/descifrado de reportes grandes en cada navegador;
- comportamiento sostenido/soak o crecimiento de tablas durante días.

Por ello, AC-37 está verificado para el presupuesto y laboratorio registrados, no como garantía de capacidad productiva. Las cifras deben vigilarse y regresionarse antes de aumentar volumen o cambiar topología; la sonda browser complementaria no debe citarse como rendimiento de la ruta Members real.
