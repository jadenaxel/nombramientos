# Desarrollo reproducible con contenedores

Esta ruta levanta el mismo build de web, API, worker, migraciones y seed que la instalación Windows, sobre PostgreSQL 18.6. Es una alternativa local de desarrollo/prueba; no modifica ni sustituye `bootstrap:local`, `start:local` o el clúster Windows existente.

No es una topología de producción. Mantiene cookies HTTP locales, secretos en el host de desarrollo y todos los procesos en una sola frontera Docker. TLS, KMS/HSM, correo, objetos, observabilidad, backups externos y WORM continúan siendo requisitos de producción separados.

En el host de esta evidencia no está disponible Docker CLI/Engine. Los Dockerfiles, Compose y contratos de runtime tienen validación estática, pero aquí no se construyeron imágenes ni se arrancaron contenedores; no debe atribuirse verificación de runtime hasta ejecutar `build`, `up` y los healthchecks en un host con Docker disponible.

## Requisitos y fronteras

- Docker Engine con Compose v2 y soporte para `service_completed_successfully` y `--wait`.
- Los puertos publicados se ligan exclusivamente a `127.0.0.1`.
- Desarrollo usa web `3300`, API `4400` y PostgreSQL `55433`; no colisiona con la ruta Windows `3000`/`4000`/`55432`.
- Prueba usa otro proyecto, imagen, directorio, volumen y puertos: `3301`, `4401` y `55434`.
- Dentro de Docker, PostgreSQL conserva el puerto `55432`. API, web, worker y bootstrap comparten solo su namespace de red y continúan usando `127.0.0.1`; el contrato de aplicación que rechaza bases no-loopback no se relaja.
- `edge` es un gateway local de dos destinos fijos. Expone los puertos publicados y reenvía únicamente a web `127.0.0.1:3000` y API `127.0.0.1:4000`.

PostgreSQL y el estado de aplicación persisten en volúmenes nombrados y aislados por `COMPOSE_PROJECT_NAME`. `postgres-data` usa `/var/lib/postgresql`, `bootstrap-private` conserva instalación, backups y accesos locales, `runtime-secrets` contiene exclusivamente `secrets.enc.json`, y `worker-state` conserva sólo estado operativo del worker. La API monta `runtime-secrets` en sólo lectura y no puede ver la URL administrativa, el inventario de backup, el acceso Demo ni el bootstrap global. Bajo `.local/container/<ambiente>/` en el host quedan únicamente los cuatro archivos fuente de Docker secrets, fuera del contexto de build y de Git.

## Desarrollo

Desde la raíz del repositorio:

```powershell
pnpm container:secrets:dev
pnpm container:config
pnpm container:up
```

El inicializador crea cuatro valores aleatorios de 32 bytes y aplica permisos restrictivos; nunca muestra sus valores. Compose los monta mediante `/run/secrets`. El bootstrap crea control/tenants, aplica migraciones a volúmenes nuevos, construye exclusivamente la Demo sintética y deja Ozama sin filas operativas.

Abra `http://localhost:3300/es/auth/sign-in`. Los cinco accesos Demo y sus URI TOTP quedan únicamente dentro del volumen privado. Para copiar el archivo v2 al directorio local protegido del operador, antes de ejecutar `container:down`:

```powershell
New-Item -ItemType Directory -Force .\.local\container\development\operator | Out-Null
docker compose --env-file .\config\container\development.compose.env cp bootstrap:/workspace/packages/database/.local/demo-access.json .\.local\container\development\operator\demo-access.json
icacls.exe .\.local\container\development\operator\demo-access.json /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):F" /grant:r '*S-1-5-18:F' | Out-Null
```

No muestre ese archivo en terminal, logs, tickets o capturas. Si necesita el material inicial de administrador global, copie de la misma forma `platform-admin-bootstrap.json`; nunca monte `bootstrap-private` en API o web.

Estado y logs sanitizados:

```powershell
docker compose --env-file .\config\container\development.compose.env ps
docker compose --env-file .\config\container\development.compose.env logs --tail 100 api web worker edge
```

Detener conserva PostgreSQL y estado:

```powershell
pnpm container:down
```

El contenedor `bootstrap` conserva un marcador ligado por hash al conjunto de secretos, inventarios de migración y build. En cada arranque vuelve a atestar PostgreSQL 18 exacto, puerto, ledgers/checksums, identidad de cada tenant, owners `NOLOGIN/NOSUPERUSER`, presencia de cada credencial cifrada y rechazo de conexión cruzada; después ejecuta de forma idempotente el emisor del bootstrap global para renovar material vencido cuando todavía no existe un administrador. No reaplica migraciones ni reescribe tenants al verificar un estado completo. Si falta el marcador, difiere el build o falla una atestación, cierra con error. Una actualización de un volumen existente requiere revisar migraciones, autorización y backup verificado conforme a `docs/operations.md`; no se adopta ni migra implícitamente al reconstruir la imagen.

## Ambiente de prueba independiente

```powershell
pnpm container:secrets:test
pnpm container:test:config
pnpm container:test:up
```

Abra `http://localhost:3301/es/auth/sign-in`. Sus secretos fuente quedan en `.local/container/test/secrets/`; sus accesos Demo viven en el volumen privado del proyecto `nombramientos-test`. No comparte volumen, estado o puertos con desarrollo.

Para dirigir Playwright a ese ambiente desde el host:

```powershell
$env:WEB_BASE_URL = 'http://localhost:3301'
$env:NEXT_PUBLIC_API_URL = 'http://localhost:4401'
$env:NOMBRAMIENTOS_E2E_TARGET = 'container-test'
New-Item -ItemType Directory -Force .\.local\container\test\operator | Out-Null
docker compose --env-file .\config\container\test.compose.env cp bootstrap:/workspace/packages/database/.local/demo-access.json .\.local\container\test\operator\demo-access.json
icacls.exe .\.local\container\test\operator\demo-access.json /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):F" /grant:r '*S-1-5-18:F' | Out-Null
$env:DEMO_ACCESS_FILE = (Resolve-Path '.\.local\container\test\operator\demo-access.json')
pnpm --filter @nombramientos/web test:e2e
Remove-Item Env:WEB_BASE_URL
Remove-Item Env:NEXT_PUBLIC_API_URL
Remove-Item Env:NOMBRAMIENTOS_E2E_TARGET
Remove-Item Env:DEMO_ACCESS_FILE
```

Detenerlo conserva únicamente sus propios datos:

```powershell
pnpm container:test:down
```

## Validación de definición e imagen

`container:config` y `container:test:config` expanden y validan Compose sin levantar servicios. Una comprobación completa de una instalación con Docker disponible es:

```powershell
pnpm container:secrets:check:dev
docker compose --env-file .\config\container\development.compose.env build
pnpm container:up
docker compose --env-file .\config\container\development.compose.env ps
```

Los servicios de larga duración tienen healthcheck: PostgreSQL usa `pg_isready`, API/web comprueban HTTP real, worker exige heartbeat reciente en control y `edge` comprueba ambos upstreams. `bootstrap` debe terminar satisfactoriamente antes de iniciar los demás.

Las imágenes usan versiones explícitas, no `latest`, pero los tags de registro siguen siendo referencias mutables si no se acompañan de un digest de la plataforma. Por ello esta entrega no afirma reproducibilidad binaria bit a bit ni trata la mera existencia de Compose como alta disponibilidad. En un pipeline de despliegue se deben resolver y aprobar digests multi-arquitectura, generar procedencia/SBOM del artefacto construido y verificar la firma antes de promoverlo.
