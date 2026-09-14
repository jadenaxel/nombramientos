# ADR-0001 — Monolito modular con workers independientes

- Estado: Aceptada
- Fecha: 2026-09-10

## Contexto

El proceso electoral requiere transacciones fuertes y una sola lógica de dominio. Microservicios prematuros aumentarían fallos distribuidos, duplicación de reglas y complejidad operativa.

## Decisión

Usar una API modular con paquetes compartidos de dominio, contratos, datos, catálogo, cifrado e i18n. Separar workers solo para trabajos durables que no deban ejecutar en la solicitud web.

## Consecuencias

- La entrega ejecuta solicitudes y sondeo SSE dentro de la API, y separa el aprovisionamiento privilegiado en un worker independiente con cola durable y heartbeat.
- Apertura, recepción y cierre permanecen en un límite transaccional claro.
- Los módulos deben impedir importaciones circulares y acceso directo a tablas ajenas.
- La extracción futura necesita métricas y una necesidad comprobada.
- No se declara alta disponibilidad por esta decisión.
