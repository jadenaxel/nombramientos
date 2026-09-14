# Dependencias, SBOM y licencias

Fecha de inventario: **13 de septiembre de 2026**.

Las versiones siguientes son las fijadas/observadas en este workspace. No se presentan como “últimas” ni como libres de vulnerabilidades futuras.

## Runtime observado

| Componente | Versión / ubicación |
|---|---|
| Node.js | v24.19.0 |
| pnpm | 11.19.0 |
| PostgreSQL | 18.6, binarios observados bajo `C:\Program Files\PostgreSQL\18\bin` |
| Clúster del proyecto | `127.0.0.1:55432`, aislado del servicio del sistema |

La raíz declara `packageManager: pnpm@11.19.0` y Node `>=24 <25`. Existe un único `pnpm-lock.yaml` autoritativo.

## Dependencias directas relevantes

| Área | Paquetes fijados | Función sensible |
|---|---|---|
| Web | Next 16.3.3; React/DOM 19.2.6 | runtime/UI |
| Estado/formularios | TanStack Query 5.102.8; React Hook Form 7.85.0; Zod 3.25.76 | red/validación |
| Documentos | pdf-lib 1.17.1; @pdf-lib/fontkit 1.1.1; ExcelJS 4.4.0 | PDF/XLSX/CSV |
| UI | Radix UI 1.6.7; Base UI 1.7.0; Lucide 1.31.0; Tailwind 4.2.1 | componentes/estilos |
| API | Fastify 5.12.1; cookie 11.0.2; CORS 11.1.0; Helmet 13.0.2; rate-limit 10.3.0 | superficie HTTP |
| Auth servidor | argon2 0.44.0; otpauth 9.4.1; @simplewebauthn/server 14.0.1 | contraseña, TOTP y verificación WebAuthn |
| Auth navegador | @simplewebauthn/browser 14.0.0; qrcode 1.5.4 | ceremonias passkey y QR TOTP generado localmente |
| Datos | pg 8.16.3 | PostgreSQL |
| E2EE | @hpke/core 1.9.0 | HPKE RFC 9180 |
| Localización | next-intl 4.14.3 | ES/EN/FR |
| Calidad | TypeScript 5.9.3; ESLint 9.39.4; Vitest 3.2.4 | análisis/pruebas |
| Navegador | Playwright 1.63.0; axe-core Playwright 4.13.0 | E2E/accesibilidad automática |

La lista completa vive en [`artifacts/sbom.cdx.json`](../artifacts/sbom.cdx.json) y [`artifacts/third-party-licenses.json`](../artifacts/third-party-licenses.json), no en esta tabla resumida.

## Pipeline reproducible

```powershell
pnpm install --frozen-lockfile
pnpm security:supply-chain
pnpm audit --prod --audit-level high
```

`security:supply-chain`:

1. ejecuta self-test del scanner;
2. inspecciona archivos fuente/configuración sin entrar a `.local-*` de cuarentena;
3. genera SBOM CycloneDX 1.6;
4. genera inventario de metadatos de licencia.

La evidencia focal actual:

- scanner self-test: aprobado;
- 1.003 archivos de entrega inspeccionados dentro del pase integral final (992 de texto, 11 binarios y 20 entradas de archivos comprimidos), 0 hallazgos de alta confianza;
- SBOM: 686 componentes;
- inventario: 686 paquetes y 0 metadatos de licencia faltantes para terceros; los siete paquetes privados del workspace se identifican por separado;
- SHA-256 de `pnpm-lock.yaml`: `ea2652f58c329ad0f1789fbecd2b2c972daebf696fa3215e5de12a499cb1ee85`;
- último `pnpm audit --prod --audit-level high` con red documentado: “No known vulnerabilities found”, incluido en el pase integral del 13-09-2026.

El resultado npm corresponde a una consulta puntual con red. No prueba ausencia de vulnerabilidades desconocidas o publicadas después.

## Cierre técnico del hallazgo transitivo

El árbol anterior de ExcelJS incluía una cadena transitiva antigua mediante una versión obsoleta de `unzipper`. El lockfile fija ahora `unzipper@0.12.5` para ExcelJS; esa cadena ya no forma parte del árbol instalado. La instalación congelada, las pruebas de compatibilidad XLSX, el SBOM y la auditoría de advisories se repiten como parte del cierre local.

El SBOM actual no tiene dependencias de terceros sin metadato de licencia. Los siete componentes sin licencia declarada son exclusivamente los paquetes privados `@nombramientos/*` del propio workspace; no son paquetes redistribuidos obtenidos del registro. Esto cierra el hallazgo técnico específico, pero no sustituye la revisión jurídica humana de todos los LICENSE/NOTICE y activos del bundle final.

## Fuentes, activos y marca

- Noto Sans se sirve localmente desde `apps/web/public/fonts/noto-sans-latin-variable.woff2`; su SIL OFL 1.1 se conserva en `apps/web/vendor/NotoSans-OFL-1.1.txt`.
- Los PDF usan subconjuntos TrueType estáticos de Bitstream Vera Sans (`report-sans-regular.ttf` y `report-sans-bold.ttf`) para interoperabilidad con lectores externos; su licencia y aviso se conservan junto a las fuentes en `apps/web/public/fonts/bitstream-vera-license.txt`.
- El aviso vendorizado de shadcn/Tailwind se conserva en `apps/web/vendor/shadcn-tailwind-4.13.0.LICENSE.md`.
- Marca, símbolos, logotipos, manuales y traducciones denominacionales no son “dependencias MIT” por formar parte de la UI. Su autorización y notices requieren revisión independiente.
- Advent Sans no se redistribuye como fuente principal del producto sin confirmar sus condiciones de marca/licencia.

## Limitaciones del inventario

- El SBOM no está firmado y no incluye attestations de procedencia/SLSA.
- El inventario lee manifests instalados; no sustituye revisar cada LICENSE/NOTICE y el bundle final.
- El scanner de secretos usa patrones de alta confianza; puede tener falsos negativos y no es un clasificador completo de PII.
- `pnpm audit` solo cubre advisories que el registro asocia al árbol consultado.
- Falta análisis SAST/DAST independiente y revisión manual de dependencias con acceso a DOM, parsers, autenticación y criptografía.
- Falta política aprobada de excepciones, cadencia de actualización y respuesta a vulnerabilidad crítica.

## Criterio de liberación

Cada build candidato debe conservar:

- lockfile revisado e instalación congelada;
- SBOM e inventario regenerados;
- auditoría de advisories con fecha/fuente;
- escaneo de secretos;
- hashes/firmas del artefacto final;
- notices jurídicamente revisados;
- explicación de cada excepción.

El último `pnpm verify:local` vuelve a generar supply chain; su resultado final debe quedar en [verification.md](verification.md).
