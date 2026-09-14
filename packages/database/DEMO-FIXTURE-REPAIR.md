# Reparación focal del fixture Demo

Este procedimiento existe únicamente para retirar el miembro sintético accidental
`ef271fe4-ecef-4b9c-bad1-4c4e9ab14dbc` del tenant Demo local. No es una herramienta
general de borrado ni debe adaptarse a otro registro o tenant.

La reparación conserva sin cambios el evento audit original, el evento outbox original
y el registro de idempotencia original. El único registro eliminado es el miembro exacto,
sin referencias FK. La misma transacción añade:

- un nuevo evento `member.changed`, usando el contrato que ya consumen SSE y la API, para
  que un consumidor vuelva a leer el padrón;
- un evento audit v2 `test.fixture.repaired`, enlazado al head existente y con los IDs de
  la evidencia original y de la compensación.

## Preflight sin escrituras

Deja PostgreSQL activo, pero detén primero API, web y worker:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop-local.ps1 -KeepDatabase
pnpm --filter @nombramientos/database db:repair:demo-fixture:check
```

Sin argumentos y con `--check`, el script sólo consulta, toma locks transitorios y termina
con `ROLLBACK`. Debe imprimir JSON con `"mode":"check"` y `"ready":true`. Cualquier otra
salida o error es un rechazo; no se debe continuar.

El preflight exige simultáneamente:

- PostgreSQL `nom_admin` en loopback y puerto aislado `55432`;
- mapping exacto del control plane y `tenant_settings` para el Demo activo;
- ausencia de `services.json`, puertos 3000/4000 cerrados, lease del worker disponible y
  ninguna otra sesión en las bases control/Demo;
- coincidencia estructural del miembro, sus sobres y hashes, audit, outbox e idempotencia;
- cadena audit válida, nueve FK conocidas y cero filas que referencien al miembro;
- manifiesto `demo-reference` v5 con hash/metadata exactos, los códigos M001–M180 y todos
  los invariantes del fixture: 181/151 antes y 180/150 después de la reparación prevista.

## Aplicación explícitamente autorizada

Compila primero la versión exacta revisada. La mutación requiere `--apply` y este token
no secreto, exacto y completo:

`AUTORIZO_REPARAR_FIXTURE_DEMO_EF271FE4_ECEF_181_A_180`

Desde la raíz del workspace:

```powershell
pnpm --filter @nombramientos/database build
pnpm --filter @nombramientos/database exec node .\scripts\repair-demo-fixture-artifact.mjs --apply "--authorization=AUTORIZO_REPARAR_FIXTURE_DEMO_EF271FE4_ECEF_181_A_180"
```

El modo apply repite el chequeo de servicios justo antes de borrar, mantiene el lease del
worker y locks de escritura durante la transacción, valida 180 miembros/150 elegibles y
la cadena audit antes del `COMMIT`. Ante cualquier discrepancia ejecuta `ROLLBACK`.

Después de un éxito no vuelvas a aplicar el script: el preflight ya no encontrará el estado
181/151 y rechazará la ejecución. Genera el siguiente checkpoint/anchor audit operativo
antes de considerar cerrado el mantenimiento y luego inicia nuevamente los servicios.
