# ADR-0002 — Base y credencial de ejecución por tenant

- Estado: Aceptada
- Fecha: 2026-09-10

## Contexto

Los datos revelan pertenencia religiosa y deliberaciones. La especificación exige aislamiento superior a una columna compartida con `tenant_id`.

## Decisión

Mantener un plano de control mínimo y crear una base PostgreSQL y rol de ejecución exclusivos por iglesia. Resolver la credencial desde la sesión validada y una referencia de secreto. No usar la credencial administrativa en tráfico ordinario.

## Consecuencias

- Migraciones, copias, restauraciones, rotación y pools son por tenant.
- Un clúster puede alojar varias bases, pero las credenciales ordinarias no deben conectarse entre ellas.
- Deben existir pruebas negativas con bases reales.
- El costo operativo crece con la cantidad de tenants y debe medirse.
