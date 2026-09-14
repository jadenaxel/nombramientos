# Backup cifrado y ensayo de restauración local

Este procedimiento cubre AC-34 para el clúster de desarrollo del workspace. Opera únicamente contra PostgreSQL 18 en `127.0.0.1:55432`; rechaza el puerto 5432, hosts no loopback, rutas de tenant no determinísticas y binarios de otra versión. No es todavía un mecanismo de producción ni una política de retención.

## Preparación y clave independiente

`local-cluster.ps1 -Action bootstrap` también ejecuta la configuración idempotente de backup. Para migrar una instalación anterior sin rotar sus demás secretos:

```powershell
pnpm --filter @nombramientos/database build
pnpm --filter @nombramientos/database db:backup:configure
```

La configuración crea `packages/database/.local/backup-keys.json` con una clave aleatoria AES-256 dedicada. `install.json` guarda solamente su ruta y la ruta verificada de los binarios PG18. Ambos archivos y los directorios de backup reciben una ACL protegida; sus valores nunca se imprimen. Si `install.json` ya referencia un inventario que falta, el script falla: no genera una clave silenciosamente que haría irrecuperables backups anteriores.

Rotación local explícita:

```powershell
pnpm --filter @nombramientos/database db:backup:key:rotate
```

La clave anterior pasa a `retired` y permanece disponible para restaurar artefactos históricos. Antes de producción se necesita custodia externa, recuperación de clave, retención, expiración y doble control aprobados. Perder el inventario local implica perder la capacidad de descifrar estos backups.

## Crear un backup de un tenant

Demo tiene un comando deliberadamente explícito:

```powershell
pnpm --filter @nombramientos/database db:backup:demo
```

Para otro tenant se exige su UUID; nunca existe una opción implícita de “todos”:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\backup-local.ps1 -Action backup -TenantId <tenant-uuid>
```

El proceso mantiene una transacción `REPEATABLE READ READ ONLY`, exporta su snapshot y entrega ese mismo snapshot a `pg_dump` 18. `PGPASSWORD` se pasa solo por el entorno del proceso hijo, no en argumentos ni salida. Antes de leer, se comprueba la coincidencia entre tenant, base determinística, rol, versión/referencia de credencial y `tenant_settings` interno.

Cada artefacto queda bajo `.local/backups/<tenant-id>/<timestamp>-<backup-id>/` y contiene:

- `database.dump.aesgcm`: dump custom/zstd cifrado mediante AES-256-GCM;
- `manifest.json`: formato/version, tenant y base origen, punto de recuperación, versión de PG/`pg_dump`, migraciones, catálogo, inventario de tablas/secuencias, cabezas de auditoría/outbox, referencia/version de credencial y `encryptionKeyId`;
- `manifest.sha256`: checksum del archivo de manifiesto para detectar corrupción accidental.

El núcleo canónico del manifiesto es AAD de AES-GCM. Se usan nonce aleatorio de 96 bits y tag de 128 bits. El manifiesto incluye SHA-256 del dump en claro, del payload cifrado y de los invariantes, pero nunca claves, contraseñas ni URLs con credenciales. El dump en claro existe únicamente dentro del área temporal protegida y se elimina en `finally`.

## Ensayo de restauración aislada

Crear un backup fresco de Demo y ensayarlo:

```powershell
pnpm --filter @nombramientos/database db:restore:drill:demo
```

Ensayar un artefacto existente:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\packages\database\scripts\backup-local.ps1 -Action drill -TenantId <tenant-uuid> -BackupDirectory <ruta-absoluta-del-artefacto>
```

La restauración solo puede crear un nombre derivado `nom_restore_<tenant8>_<backup8>`. Antes de crear comprueba que:

1. el destino cumple exactamente ese patrón;
2. no coincide con ninguna base registrada ni con `nom_t_*`;
3. no existe previamente (si existe, se rehúsa a sobrescribirlo o borrarlo);
4. el manifiesto/checksum/payload/tag son válidos y pertenecen al tenant solicitado;
5. existe otro tenant elegible para mantenimiento cuya huella pueda compararse antes y después, incluido un tenant pendiente de activación cuando corresponda.

`pg_restore` recibe siempre el scratch explícito, sin `--create`, owner ni privilegios del dump. Después se comparan tenant/kind/catálogo, migraciones, cada fila de cada tabla mediante hash canónico, conteos, secuencias y cabezas de auditoría/outbox. También se recalcula la huella completa del otro tenant. El scratch y el dump descifrado se eliminan en bloques `finally`; un fallo de limpieza convierte el ensayo en fallo visible.

La salida es JSON sanitizado. `recoveryPointAgeMs` mide conservadoramente desde el snapshot hasta el fin de la verificación (evidencia RPO); `restoreTimeMs` incluye descifrado, baseline del tenant vecino, creación, restauración, verificación y aislamiento (evidencia RTO). Los objetivos iniciales son RPO ≤ 15 minutos y RTO ≤ 4 horas. Para una medición estable no debe haber escritores legítimos sobre el tenant vecino durante el ensayo, pues cualquier cambio real causa un fallo seguro de aislamiento.

## Evidencia local del 2026-09-11

Un ensayo real sobre el dataset sintético Demo, con Ozama como tenant vecino, produjo:

- backup autenticado y restauración: `passed`;
- coincidencia íntegra de invariantes: `true`;
- Ozama sin cambios durante el ensayo: `true`;
- scratch eliminado: `true`;
- creación del backup: 0.272 s;
- edad del punto de recuperación al terminar la verificación y limpieza: 0.922 s (objetivo RPO cumplido);
- restauración/verificación/limpieza: 0.675 s (objetivo RTO cumplido; la fase posterior al descifrado fue 0.668 s);
- operación completa, incluida la carga y validación del contexto local: 1.023 s.

Estas cifras prueban el dataset y equipo local actuales; no son una garantía de capacidad para volúmenes ni infraestructura de producción.
