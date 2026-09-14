# ADR-0005 — Catálogo normativo e idiomas versionados

- Estado: Aceptada
- Fecha: 2026-09-10

## Decisión

Versionar reglas, departamentos, cargos, nombres y traducciones. Cada ciclo guarda la versión exacta. Las ampliaciones locales no modifican la referencia canónica. Las traducciones de trabajo no se presentan como oficiales.

## Consecuencias

- Actualizar un nombre no reescribe informes históricos.
- El build debe fallar si ES/EN/FR no comparten las mismas claves.
- Orden y hash de boleta no dependen del locale personal.
- La jurisdicción de Ozama debe confirmarse antes de marcar el paquete como validado.
