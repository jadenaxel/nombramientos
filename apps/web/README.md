# Cliente web

Interfaz Next.js de Nombramientos Adventistas. Se ejecuta como parte del workspace raíz; consulte [la guía principal](../../README.md) para instalación, arranque y verificación contra PostgreSQL/API reales.

Comandos del paquete:

```powershell
pnpm dev
pnpm build
pnpm start
pnpm typecheck
pnpm lint
pnpm test:e2e
```

`NEXT_PUBLIC_API_URL` usa `http://localhost:4000` por defecto. Abra siempre la interfaz local en `http://localhost:3000`: mantener web, cookies y WebAuthn bajo el mismo nombre canónico evita sesiones fragmentadas. Los procesos continúan enlazados internamente a `127.0.0.1`. No guarde claves de contenido ni tokens persistentes en el cliente: el vault de contenido vive únicamente en memoria y se limpia al salir, al vencer la sesión o al cambiar de tenant.
