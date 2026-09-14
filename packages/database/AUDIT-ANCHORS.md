# Checkpoints y anclajes de auditoría

Este paquete contiene una primitive criptográfica pura y una herramienta operativa local, sin migraciones, para ensayar la detección exigida por AC-33. No convierte PostgreSQL, el repositorio o el disco local en almacenamiento WORM.

## Qué implementa

`src/audit-anchors.ts` proporciona:

- recomputación del hash canónico ya utilizado por `audit_events` y validación estricta de secuencias y enlaces;
- checkpoints acumulativos con cabeza, cobertura, enlace al checkpoint anterior y firma Ed25519;
- una cadena de anclajes separada de la cadena de eventos, también enlazada y firmada con Ed25519;
- un recibo de cabeza que debe conservarse fuera de la base y del backup que se está verificando;
- verificación fail-closed con códigos estables para contenido alterado, borrado, truncamiento, reordenación, firma inválida, anclaje modificado y rollback a una cadena antigua.

Los hashes de checkpoint y anclaje usan SHA-256 con separación de dominio. Las firmas de checkpoints y anclajes también tienen dominios distintos y pueden usar llaves distintas. Las secuencias PostgreSQL `bigint` se representan como cadenas decimales para no perder precisión en JavaScript. Se exige orden estrictamente creciente, no contigüidad: una secuencia puede dejar huecos legítimos cuando una transacción consume un valor y revierte; la eliminación de una fila se detecta mediante el enlace/hash y el checkpoint firmado.

## Flujo de integración previsto

1. Leer una instantánea consistente de `audit_events` y verificar por completo hashes, enlaces y orden creciente.
2. Crear un checkpoint acumulativo de la cadena nativa válida y firmarlo con una llave Ed25519 dedicada a checkpoints.
3. Escribir ese checkpoint en un almacén append-only separado.
4. Crear el siguiente anclaje, enlazado con la cabeza anterior, y firmarlo con una llave Ed25519 independiente.
5. Persistir el anclaje y su recibo de cabeza fuera de la base tenant, sus credenciales, su volumen y su conjunto de backups.
6. Al verificar o restaurar, obtener la cabeza confiable desde ese destino independiente y ejecutar `verifyAnchoredAuditTrail`.

La verificación estricta exige que el último checkpoint cubra el último evento presentado y que haya exactamente un anclaje ordenado por checkpoint. Los eventos posteriores al último anclaje todavía no disfrutan detección de truncamiento: deben checkpointarse y anclarse antes de afirmar cobertura.

## Herramienta local

Compila el paquete y utiliza siempre el wrapper, que valida el endpoint y aplica ACL al inventario y los artefactos:

```powershell
pnpm --filter @nombramientos/database build
powershell -NoProfile -ExecutionPolicy Bypass -File packages/database/scripts/audit-anchor-local.ps1 -Action configure
powershell -NoProfile -ExecutionPolicy Bypass -File packages/database/scripts/audit-anchor-local.ps1 -Action checkpoint -TenantId d0000000-0000-4000-8000-000000000001
powershell -NoProfile -ExecutionPolicy Bypass -File packages/database/scripts/audit-anchor-local.ps1 -Action verify -TenantId d0000000-0000-4000-8000-000000000001
powershell -NoProfile -ExecutionPolicy Bypass -File packages/database/scripts/audit-anchor-local.ps1 -Action drill -TenantId d0000000-0000-4000-8000-000000000001
```

No existe valor implícito ni acción para «todos los tenants»: `checkpoint`, `verify` y `drill` exigen un UUID explícito. La herramienta rechaza puerto 5432, hosts no loopback, usuarios distintos de `nom_admin`, rutas fuera de `packages/database/.local` y enlaces simbólicos en artefactos. El control plane y la base tenant se leen dentro de transacciones `REPEATABLE READ READ ONLY`; no se ejecuta `INSERT`, `UPDATE`, `DELETE`, DDL ni escritura sobre Demo/Ozama.

La herramienta es fail-closed: si la historia existente ya contiene un hash o enlace roto, no crea un baseline, no repara filas y no publica un recibo. Debe reconstruirse o recuperarse el entorno por el procedimiento autorizado y solo entonces generar el primer checkpoint.

El layout es deliberadamente separado de las bases y los backups:

```text
packages/database/.local/
├─ audit-signing-keys.json          # inventario privado; checkpoint y anclaje usan llaves distintas
└─ audit-anchors/
   ├─ ledgers/<tenant-id>/          # generaciones acumulativas e inmutables por nombre
   ├─ receipts/<tenant-id>/         # recibos inmutables, uno por generación
   ├─ locks/                        # exclusión por tenant/inventario
   └─ work/                         # copias temporales del drill; eliminación exacta en finally
```

Cada archivo se crea con nombre nuevo mediante temporal exclusivo, `fsync` y enlace atómico; nunca se sobrescribe una generación existente. El recibo expone tenant, stream, secuencia y hashes, pero no eventos, URL, contraseña ni llave privada. `verify` toma el recibo más reciente disponible y valida la base actual, todas las firmas y las dos cadenas. `drill` copia ledger/recibo a `work`, altera solo objetos en memoria y elimina la carpeta temporal exacta antes de emitir éxito.

## Evidencia automatizada local

```powershell
pnpm --filter @nombramientos/database typecheck
pnpm --filter @nombramientos/database test
```

`test/audit-anchors.test.ts` construye dos checkpoints y dos anclajes con pares Ed25519 separados. `test/audit-anchor-ledger.test.ts` valida generaciones, recibos, límites de conexión y rechazo de traversal. Juntas demuestran rechazo de:

- modificación de un evento;
- reescritura con recálculo completo de los hashes internos;
- eliminación de un evento intermedio;
- truncamiento de la cola;
- reordenación;
- restauración de una cadena antigua internamente válida frente a una cabeza posterior;
- firma de checkpoint alterada o llave pública incorrecta;
- contenido o firma de anclaje alterados;
- eliminación de un anclaje.

Las pruebas nuevas son puras: no abren conexiones, no escriben Demo/Ozama y no modifican el clúster PostgreSQL local. La prueba operativa se realiza por separado con `checkpoint` y `verify`, ambos en transacciones de solo lectura.

## Límite del entorno local

El ledger local bajo `.local` es **una emulación de desarrollo, no retención WORM**. Las generaciones no se sobrescriben por la API de la herramienta y reciben ACL restringida, pero un administrador del equipo puede borrar o reemplazar el inventario, ledgers y recibos. Si borra conjuntamente la cabeza más reciente y su recibo local, no queda una referencia verdaderamente independiente que pruebe el rollback. El inventario usa PEM exportable en disco, no KMS/HSM. Tampoco existe todavía un scheduler, rotación de llaves ni publicación hacia otro dominio administrativo.

Antes de producción se requiere, como mínimo:

- un destino WORM real con retención bloqueada y credenciales independientes;
- llaves privadas no exportables en KMS/HSM, separación entre firma de checkpoints y anclajes, rotación y revocación documentadas;
- publicación/lectura de recibos desde otra cuenta o dominio administrativo;
- monitoreo de retraso, huecos, fallos de firma y falta de anclajes;
- ensayo de restauración que consulte el anclaje externo, además del manifiesto del backup;
- revisión criptográfica y operacional independiente.

La garantía es detección hasta la última cabeza externa confiable. No es invulnerabilidad ante quien controle simultáneamente la infraestructura primaria, el destino independiente, todas las llaves y los recibos.
