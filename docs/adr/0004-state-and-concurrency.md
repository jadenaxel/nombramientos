# ADR-0004 — Máquina de estados, idempotencia y cierre atómico

- Estado: Aceptada
- Fecha: 2026-09-10

## Decisión

Separar estados de proceso, ronda, candidatura, consentimiento y asignación. Toda mutación crítica incluye versión esperada e idempotencia. La base de datos decide de forma atómica si un envío precedió al cierre.

## Consecuencias

- No existe un endpoint genérico para escribir cualquier estado.
- Un borrador no cuenta; un acuse confirmado sí.
- Reintentos y dos pestañas no crean dos participaciones.
- Cambiar padrón o reglas de una ronda abierta exige anulación y nueva versión.
