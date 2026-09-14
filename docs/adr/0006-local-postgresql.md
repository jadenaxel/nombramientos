# ADR-0006 — PostgreSQL local aislado para desarrollo

- Estado: Aceptada para desarrollo; producción pendiente
- Fecha: 2026-09-10

## Decisión

Usar PostgreSQL 18 en un clúster del proyecto enlazado a `127.0.0.1:55432`, con datos dentro de `packages/database/.local`, sin modificar ni reutilizar silenciosamente un servicio PostgreSQL existente. `-Action bootstrap` crea de forma no interactiva credenciales aleatorias por instalación y las guarda con ACL restringida en `.local/install.json`, sin imprimirlas.

## Consecuencias

- Los scripts deben rechazar hosts no loopback en modo local.
- Datos, puerto, logs y roles de desarrollo no equivalen a una configuración de producción.
- No se incluyen contraseñas en Git.
- Los binarios PostgreSQL 18.6 fueron observados en la ruta predeterminada del equipo y el verificador confirmó servidor major 18; la ejecución integrada se registra como evidencia separada y el real-stack autorizado 3/3 pasó el 13-09-2026 sin alterar las bases protegidas.
- `bootstrap` solo inicializa clúster y configuración: inicio, migración, aprovisionamiento, seed y pruebas permanecen como pasos explícitos.
- `.local/install.json` y `.local/demo-access.json` son secretos de desarrollo ignorados por Git, no sustituyen un gestor de secretos de producción.
