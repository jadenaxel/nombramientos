# PROMPT DE EJECUCIÓN — INSCRIPCIÓN MFA HUMANA, QR EN PC Y RETIRO DE SECRETOS EN ARCHIVOS

## 1. Mandato

Implementar de extremo a extremo la corrección del alta y primer acceso MFA de **Nombramientos**. El resultado debe ser seguro, usable, verificable y completamente funcional con el backend, frontend, PostgreSQL local, migraciones, seed Demo, automatización, documentación y pruebas conectados entre sí.

No declarar “100%”, “enterprise-grade”, “completado” ni equivalentes basándose solamente en pruebas unitarias o mocks. La declaración de cierre requiere demostrar en un navegador real el recorrido humano desde una cuenta sin MFA hasta una sesión operativa AAL2, sin consultar archivos que contengan contraseñas, semillas TOTP o códigos de verificación.

Trabajar autónomamente hasta completar todos los criterios de aceptación. No detenerse por problemas ordinarios de implementación: diagnosticar, corregir, volver a probar y documentar. Pedir intervención humana únicamente si aparece una decisión de producto irreductible, una credencial externa que no existe o una acción destructiva fuera del alcance aquí autorizado.

## 2. Resultado obligatorio

Para un usuario humano que entra desde una PC, el flujo principal debe ser exactamente:

```text
Correo + contraseña
        ↓
Credenciales verificadas
        ↓
Sesión temporal enrollment_only, sin acceso operativo
        ↓
Asistente obligatorio de protección de cuenta
        ↓
QR TOTP generado localmente y mostrado en la PC
        ↓
Escaneo con la aplicación autenticadora del celular
        ↓
Confirmación del primer código de seis dígitos
        ↓
Códigos de recuperación mostrados una sola vez
        ↓
Revocación de la sesión temporal
        ↓
Nueva sesión AAL2
        ↓
Acceso completo según roles y tenant
```

El usuario **no recibe ni busca un código asignado por un administrador**. El autenticador del teléfono genera un código TOTP nuevo aproximadamente cada 30 segundos después de escanear el QR. El factor no se considera activo hasta que el backend verifica correctamente el primer código.

En teléfono debe conservarse el deep link `otpauth:` para abrir una aplicación autenticadora sin escanear la misma pantalla. Passkeys/FIDO2 pueden permanecer disponibles como método más resistente al phishing y como requisito adicional para perfiles privilegiados si la política lo exige, pero en PC el alta TOTP mediante QR debe ser una opción principal, clara y completamente funcional.

## 3. Diagnóstico conocido que debe corregirse

El estado actual contiene una contradicción entre el flujo humano y la automatización:

1. `packages/database/scripts/seed-demo.ts` crea o reutiliza contraseñas y URI de inscripción TOTP para los perfiles Demo.
2. `packages/database/src/demo-access.ts` modela `password` y `totpEnrollmentUri` como material obligatorio para cada perfil.
3. `packages/database/.local/demo-access.json` conserva contraseñas recuperables y URI `otpauth:` con semillas TOTP.
4. El seed deja perfiles Demo humanos con `mfa_enabled=true` antes de que la persona haya inscrito su autenticador.
5. `apps/api/src/modules/auth-service.ts` interpreta ese estado como un MFA ya configurado y entrega un challenge de código inmediatamente después de la contraseña.
6. `apps/web/components/nombramientos/login-form.tsx` muestra “Verificación en dos pasos”, aunque la persona nunca recibió ni configuró la semilla.
7. `apps/web/e2e/support/demo-auth.ts`, pruebas live y otros scripts leen `demo-access.json`, calculan el TOTP y hacen pasar el recorrido automatizado.
8. El recorrido de invitaciones y `enrollment_only` ya implementa gran parte de la arquitectura correcta, pero el fixture Demo humano lo evita.

La solución no debe limitarse a cambiar textos o a mostrar el QR existente. Debe eliminar el acoplamiento inseguro y corregir el ciclo de vida completo de la identidad.

## 4. Decisiones de seguridad no negociables

### 4.1 Sesión posterior a la contraseña

Cuando una identidad tenga `mfa_required=true` y todavía no posea un factor confirmado:

- validar la contraseña con el mecanismo existente;
- emitir exclusivamente una cookie de sesión `HttpOnly` con assurance `enrollment_only`;
- limitarla en servidor y base de datos a un máximo de diez minutos;
- enlazarla a la identidad, contexto, user-agent/IP según la política existente y ceremonia de alta;
- entregar CSRF por el canal existente, sin exponer el token de sesión en JSON;
- no entregar roles operativos, permisos tenant ni llaves de contenido E2EE;
- permitir únicamente inspección mínima de sesión/policy, inicio/consulta/cancelación/confirmación del alta MFA, alta passkey cuando proceda y logout;
- bloquear por defecto cualquier otra ruta mediante autorización central, no mediante una lista dispersa solo en la UI.

La interfaz puede comunicar “Credenciales verificadas; falta proteger la cuenta”, pero no debe representar la sesión como acceso completo.

### 4.2 Ciclo de vida TOTP

Implementar y probar explícitamente los estados equivalentes a:

```text
not_enrolled → pending → active
                    ↘ cancelled / expired
```

Requisitos:

- generar la semilla con el CSPRNG del sistema operativo;
- guardar la semilla pendiente cifrada con AES-256-GCM usando el mecanismo de secretos del servidor ya existente;
- devolver la URI `otpauth:` únicamente en la respuesta inicial de la ceremonia;
- usar `Cache-Control: no-store` y no registrar cuerpo, URI, secreto ni QR;
- generar el QR localmente dentro del frontend; está prohibido enviar la URI a Google Charts, servicios de QR o cualquier tercero;
- no guardar semilla ni URI en `localStorage`, `sessionStorage`, IndexedDB, cookies, telemetría, analytics, reportes, screenshots automatizados o artefactos;
- permitir en `sessionStorage` solamente un identificador opaco de inscripción y su expiración si el diseño actual lo requiere;
- no volver a publicar la semilla después de una recarga; permitir confirmar o cancelar/reiniciar;
- activar TOTP únicamente después de verificar un código válido;
- hacer la activación, consumo de ceremonia, revocación de sesión bootstrap y emisión de sesión AAL2 dentro de una frontera transaccional que no deje estados parciales;
- cancelar o expirar elimina el estado pendiente y vuelve a `not_enrolled` sin activar el factor;
- conservar los límites de intentos, rate limits, protección contra replay y auditoría existentes.

### 4.3 Recuperación

- Generar códigos de recuperación criptográficamente aleatorios después de confirmar el factor.
- Mostrar su texto plano una sola vez y exigir una confirmación clara de guardado.
- Guardar únicamente hashes Argon2id de códigos de recuperación.
- Nunca escribirlos en archivos, logs, respuestas posteriores o reportes de pruebas.
- El reemplazo de un MFA ya activo exige un factor fuerte existente o el flujo de recuperación gobernada; una contraseña por sí sola no puede sustituir un factor activo.

### 4.4 Datos y secretos

- Las contraseñas de usuario solo pueden persistirse como hash Argon2id.
- Una semilla TOTP activa debe persistirse únicamente cifrada porque el servidor necesita recuperarla para validar TOTP; nunca en texto plano ni en un URI persistente.
- Una passkey persiste únicamente material público y metadatos permitidos.
- La rotación de contraseñas no puede romper los grants o envelopes E2EE. Identificar primero cómo la contraseña Demo participa en el unwrap de llaves de contenido y diseñar la reemisión o rewrap correcto antes de invalidarla.
- Eliminar un archivo no neutraliza una credencial ya expuesta. Toda contraseña o semilla presente en `demo-access.json` debe rotarse o invalidarse.

## 5. Retiro de `demo-access.json`

### 5.1 Alcance

Retirar `packages/database/.local/demo-access.json` como fuente de autenticación humana o automatizada y eliminar sus dependencias activas en, como mínimo:

- `packages/database/src/demo-access.ts`;
- `packages/database/scripts/seed-demo.ts`;
- `packages/database/test/demo-access.test.ts`;
- `packages/database/test/demo-access-profiles.live.test.ts`;
- `apps/api/test/live.integration.test.ts`;
- `apps/web/e2e/support/demo-auth.ts`;
- `scripts/bootstrap-local.ps1`;
- `scripts/verify-local.ps1`;
- `scripts/scan-secrets.mjs` y sus pruebas, manteniendo o reforzando detección de regresiones;
- `docs/operations.md`;
- `docs/container-development.md`;
- `README.md`;
- artefactos, scripts auxiliares y cualquier otra referencia encontrada con búsqueda completa del repositorio.

No asumir que esta lista es exhaustiva. Ejecutar búsquedas por `demo-access`, `DEMO_ACCESS_FILE`, `totpEnrollmentUri`, `totpSecret`, `otpauth`, lectura de credenciales y generadores TOTP.

### 5.2 Sustitución para humanos Demo

Los perfiles humanos Demo deben conservar sus identidades, roles, membresías y datos operativos, pero quedar inicialmente con:

```text
mfa_required = true
mfa_enabled = false
mfa_enrolled_at = NULL
totp_secret_ciphertext = NULL
sin recovery codes anteriores
sin sesiones/challenges/grants heredados
```

Las credenciales antiguas deben considerarse comprometidas. Implementar una ceremonia segura para provisionar o restablecer la contraseña sin conservarla en un archivo:

- reutilizar preferentemente la infraestructura de invitación/activación de un solo uso ya existente;
- almacenar solamente el hash del token de activación;
- entregar el token una sola vez por un canal local de operador explícito en desarrollo, nunca en logs generales ni artefactos;
- permitir que cada persona establezca su propia contraseña;
- después de establecerla, descartar definitivamente el token;
- en producción, fallar cerrado si no existe un adaptador de entrega fuera de banda aprobado;
- no introducir contraseñas universales, deterministas, compartidas o codificadas en el repositorio.

Si el flujo existente permite completar inscripción inmediatamente después de aceptar una invitación, mantener la misma frontera `enrollment_only`; no crear una segunda implementación paralela.

### 5.3 Migración de los cinco perfiles actuales

Crear una migración o reparación forward-only, acotada por los IDs fijos y tenant Demo, que:

1. Tome locks apropiados y falle cerrado si la identidad/tenant no coincide con las huellas esperadas.
2. Invalide las semillas TOTP expuestas y recovery codes relacionados.
3. Revoque sesiones, challenges MFA, ceremonias y grants derivados de las credenciales expuestas.
4. Invalide o reemplace los hashes de las contraseñas antiguas sin conservar su preimagen.
5. Preserve membresías, roles, rondas, nombramientos, auditoría funcional y demás datos operativos.
6. Preserve o reemita correctamente los grants E2EE; demostrar que el usuario autorizado todavía puede desbloquear su contenido después de establecer la nueva contraseña.
7. Registre un evento de auditoría sin incluir secretos.
8. Sea idempotente o falle de manera inequívoca ante una segunda ejecución.
9. Se ejecute únicamente contra PostgreSQL local esperado en `127.0.0.1:55432` durante esta reparación y respete los guardas de Demo/Ozama existentes.

Antes y después, capturar y comparar huellas y conteos de control, Demo y Ozama. No modificar datos Ozama ni datos Demo fuera del alcance de autenticación descrito.

Una vez rotadas/invalidadas las credenciales, retirar de forma recuperable el archivo local exacto. No usar borrados recursivos ni patrones amplios. El cierre debe indicar qué archivo se retiró y por qué sus copias históricas ya no conceden acceso.

## 6. Separación de automatización y usuarios humanos

Las pruebas no deben volver a convertir un secreto humano en fixture de automatización.

Implementar un harness de pruebas que:

- cree identidades, contraseñas y semillas exclusivamente efímeras;
- use bases y roles UUID temporales donde corresponda;
- mantenga el material sensible solamente en memoria del proceso coordinador;
- pase datos entre API y navegador mediante memoria/IPC acotado, no mediante archivos persistentes, reportes o variables heredadas a procesos no relacionados;
- destruya cuentas, roles, bases y secretos efímeros al finalizar, incluso ante fallos;
- nunca use los cinco perfiles humanos Demo para calcular códigos TOTP automáticamente;
- nunca publique contraseñas, URI `otpauth:` o códigos en traces, videos, screenshots, HTML reports o JSON de cierre;
- conserve cobertura de roles mediante sesiones de prueba efímeras o mecanismos públicos de aprovisionamiento, no saltándose el flujo de seguridad del producto.

Agregar una prueba de regresión que falle si código runtime, live tests o Playwright vuelve a leer `demo-access.json` o cualquier equivalente con secretos humanos.

## 7. Backend requerido

Revisar y ajustar, como mínimo:

- `apps/api/src/modules/auth-service.ts`;
- `apps/api/src/modules/auth-routes.ts`;
- stores de control/MFA/sesiones;
- policy enforcement central;
- migraciones y grants PostgreSQL;
- OpenAPI y tipos compartidos.

Comportamiento obligatorio:

1. Contraseña válida + MFA requerido + ningún factor activo devuelve una sesión `enrollment_only`, no `mfa_required` con challenge de código.
2. Contraseña válida + TOTP ya activo devuelve `mfa_required` y exige código, como hoy.
3. Contraseña válida + factor perdido no revela ni regenera la semilla; ofrece recuperación.
4. Una sesión `enrollment_only` no puede consultar datos tenant, roles operativos, reportes, rondas, miembros, propuestas, votos, llaves de contenido ni operaciones privilegiadas.
5. El inicio de alta TOTP entrega el material sensible solamente una vez y con `no-store`.
6. La confirmación válida activa el factor y emite AAL2 atómicamente.
7. Código incorrecto, repetido, vencido, fuera de ventana o con challenge agotado falla cerrado y respeta rate limits.
8. Cancelación, logout, expiración, suspensión de identidad, cambio de policy o revocación de invitación invalidan la ceremonia pendiente según corresponda.
9. Toda respuesta y auditoría omite secretos.

No confiar en controles frontend para imponer estas restricciones.

## 8. Frontend y experiencia de usuario

Revisar y ajustar, como mínimo:

- `apps/web/components/nombramientos/login-form.tsx`;
- `apps/web/components/nombramientos/mfa-enrollment.tsx`;
- AppShell, Centro de seguridad, guards y navegación;
- cliente API, tipos e i18n ES/EN/FR.

### 8.1 Pantalla posterior a contraseña

Para `enrollment_only`, mostrar un asistente inequívoco y no la pantalla de “introduce el código de tu aplicación”:

- título: “Protege tu cuenta”;
- explicación breve: las credenciales fueron verificadas y falta vincular un autenticador;
- opción PC prominente: “Configurar con código QR”;
- explicación de que debe abrir una aplicación autenticadora en su teléfono y escanear el QR;
- ejemplos neutrales de aplicaciones compatibles sin exigir una marca específica;
- opción móvil: “Abrir mi aplicación autenticadora”;
- passkey como opción adicional o exigida por policy;
- alternativa manual accesible, secundaria y revelada bajo acción explícita;
- botón de cancelar que cierre la sesión restringida de forma segura.

### 8.2 QR en PC

- Detectar/presentar el contexto PC sin depender exclusivamente de user-agent frágil; el usuario siempre puede seleccionar QR manualmente.
- Generar el QR localmente desde la URI recibida una sola vez.
- Tamaño, contraste, quiet zone y corrección de error adecuados.
- Etiqueta accesible y explicación textual; el secreto manual debe poder copiarse mediante control accesible.
- No incluir la URI en atributos innecesarios, analytics, mensajes de error o DOM después de confirmar/cancelar.
- Vaciar estado sensible en memoria al desmontar, confirmar, cancelar, expirar o cerrar sesión.

### 8.3 Confirmación y recuperación

- Campo segmentado o equivalente accesible para seis dígitos con paste, teclado físico y lectores de pantalla.
- Estados claros: verificando, código inválido, expirado, demasiados intentos, sesión vencida y reintento seguro.
- Tras éxito, mostrar códigos de recuperación una sola vez, con descargar/imprimir/copiar solo por acción del usuario y advertencia de almacenamiento seguro.
- No navegar al área operativa hasta que el backend confirme la nueva sesión AAL2.
- En recarga, nunca intentar reconstruir la semilla desde almacenamiento; permitir continuar confirmación si queda un `enrollmentId` válido o reiniciar.

### 8.4 Calidad visual y accesibilidad

- Diseño consistente con el sistema visual existente, responsive y sin desbordes a 320 px.
- Navegación completa por teclado, foco visible, orden lógico, labels asociados y mensajes anunciados con live regions.
- Contraste WCAG 2.2 AA como mínimo, targets táctiles adecuados y respeto a reduced motion.
- Paridad funcional y textual ES/EN/FR sin claves faltantes.

## 9. Matriz mínima de pruebas

### 9.1 Unitarias y de contrato

- Password login de cuenta no inscrita produce `enrollment_only`.
- Cuenta ya inscrita sigue produciendo challenge TOTP.
- Factor pendiente no se considera activo.
- Confirmación correcta rota a AAL2.
- Confirmación incorrecta no altera identidad ni sesión.
- Expiración/cancelación elimina pending state.
- Recovery codes se hashean y consumen una vez.
- Ningún serializer, logger o error publica secreto/URI/código.
- Autorización central niega cada ruta operativa a `enrollment_only`.
- Migración exacta de los cinco perfiles y guardas contra targets inesperados.

### 9.2 Integración PostgreSQL real

- Ejecutar el flujo contra PostgreSQL local real en `55432`.
- Verificar transacciones y rollback bajo fallos inducidos.
- Verificar concurrencia: doble confirmación, cancelación simultánea, revocación/suspensión concurrente y replay.
- Verificar que Demo/Ozama mantienen huellas y conteos fuera del ámbito autorizado.
- Verificar que los grants E2EE posteriores a la rotación permiten al usuario correcto desbloquear y no amplían acceso a otros roles.

### 9.3 E2E navegador real — recorrido humano obligatorio

Crear una cuenta humana de prueba limpia y demostrar en Chromium y WebKit obligatorios:

1. Abrir sign-in en PC.
2. Introducir correo y contraseña.
3. Recibir el asistente “Protege tu cuenta”, no una solicitud de código previamente desconocido.
4. Comprobar que las rutas operativas devuelven denegación antes de completar MFA.
5. Mostrar QR local.
6. Inscribir un autenticador controlado por el test sin leer secretos humanos ni archivos persistentes.
7. Confirmar el primer código.
8. Mostrar recovery codes una sola vez.
9. Entrar con la sesión AAL2 y permisos correctos.
10. Cerrar sesión.
11. Volver a entrar con contraseña + TOTP y verificar el comportamiento de un factor ya activo.
12. Probar código erróneo, replay, recovery code de un uso, reload, cancelación y expiración.

Agregar variantes:

- viewport PC y teléfono;
- ES/EN/FR;
- teclado solamente;
- usuario administrador y al menos un rol restringido;
- cuenta sin MFA requerido cuando la policy lo permita;
- cuenta con passkey activa;
- pérdida de factor que dirige a recuperación y nunca revela semilla.

Los traces/videos/screenshots solo pueden activarse si existe sanitización demostrada. Escanear todos los artefactos al finalizar.

## 10. Comandos de validación y cierre

Descubrir primero los scripts vigentes y no inventar resultados. Como mínimo, ejecutar y dejar verdes:

```powershell
pnpm typecheck
pnpm lint
pnpm test
pnpm security:secrets
pnpm test:e2e
pnpm test:e2e:real-stack:check
pnpm test:e2e:real-stack:local
pnpm verify:local
```

Si una suite crea/elimina bases o roles efímeros, verificar previamente sus guardas de seguridad y documentar targets exactos. No tocar servicios ajenos ni puertos fuera del alcance. No ocultar fallos, no convertir fallos obligatorios en skips y no relajar assertions para obtener verde.

Ejecutar además búsquedas de cierre que demuestren:

- cero lectores activos de `demo-access.json`;
- cero contraseñas o URI TOTP persistidas en fixtures humanos;
- cero secretos en Git, logs, `.next`, dist, reports y `artifacts` publicables;
- documentación consistente con el comportamiento real;
- ningún texto que instruya a buscar códigos MFA en archivos.

## 11. Orden de ejecución recomendado

1. Capturar baseline: estado de servicios, tests, esquema, huellas y conteos.
2. Trazar todas las dependencias de `demo-access.json` y del password Demo en E2EE.
3. Diseñar la migración forward-only y el aprovisionamiento humano de reemplazo.
4. Agregar primero pruebas que reproduzcan el defecto humano actual.
5. Corregir modelo/seed/migración de identidades Demo.
6. Corregir backend y frontera `enrollment_only`.
7. Conectar el asistente frontend y QR de PC.
8. Sustituir el harness de automatización por identidades efímeras.
9. Retirar archivo, lectores, scripts y documentación obsoleta.
10. Ejecutar pruebas focalizadas.
11. Ejecutar suites completas y real-stack.
12. Probar manualmente con navegador real el recorrido de un usuario humano.
13. Escanear secretos y artefactos.
14. Comparar huellas/conteos y publicar evidencia final precisa.

## 12. Prohibiciones

Está prohibido:

- pedir al usuario que abra un archivo para obtener un código MFA;
- preinscribir TOTP para una cuenta humana;
- guardar contraseñas, semillas, URI `otpauth:` o recovery codes en archivos;
- mostrar directamente el formulario de seis dígitos a alguien que nunca confirmó un autenticador;
- emitir sesión operativa antes de MFA cuando la policy lo exige;
- considerar un mock frontend como evidencia del flujo real;
- usar servicios externos para generar QR;
- sustituir un factor activo usando solo contraseña;
- mezclar usuarios humanos Demo con identidades de automatización;
- romper o recrear silenciosamente datos operativos para facilitar la reparación;
- declarar éxito con suites obligatorias omitidas, congeladas o fallidas;
- publicar credenciales en el informe final.

## 13. Definición estricta de “100% completado”

Solo declarar terminado cuando se cumplan simultáneamente todos estos puntos:

- [ ] Un usuario humano nuevo en PC entra con correo y contraseña y recibe inscripción, no un código imposible.
- [ ] El QR se genera localmente y permite vincular un autenticador real.
- [ ] TOTP queda inactivo hasta la primera confirmación válida.
- [ ] `enrollment_only` no puede acceder a ningún dato o permiso operativo.
- [ ] Confirmación rota atómicamente a una sesión AAL2.
- [ ] Recovery codes se muestran una vez y solo persisten hasheados.
- [ ] Los cinco perfiles Demo ya no dependen de secretos preinscritos.
- [ ] Contraseñas y semillas anteriormente expuestas fueron rotadas/invalidadas.
- [ ] El acceso E2EE legítimo sigue funcionando después de la rotación.
- [ ] `demo-access.json` y sus equivalentes dejaron de ser fuentes de credenciales.
- [ ] Automatización usa identidades y secretos efímeros separados.
- [ ] Chromium y WebKit demuestran el recorrido humano contra stack real.
- [ ] Unit, integration, E2E, typecheck, lint, seguridad y verificación local están verdes.
- [ ] No hay regresiones en Demo/Ozama fuera del alcance autorizado.
- [ ] No hay secretos en código, archivos, logs ni artefactos publicables.
- [ ] Documentación ES/técnica coincide con el producto ejecutable.
- [ ] El informe final distingue evidencia local, limitaciones externas y cualquier control que requiera infraestructura productiva.

## 14. Entrega final exigida

Entregar un informe final con:

1. Causa raíz corregida.
2. Archivos y migraciones modificados.
3. Explicación del nuevo flujo PC, móvil y accesos posteriores.
4. Tratamiento exacto de contraseñas, semillas y archivo retirado.
5. Evidencia de preservación E2EE y datos Demo/Ozama.
6. Tabla de suites ejecutadas con comando, resultado, conteo y duración.
7. Evidencia del E2E real desde primera contraseña hasta AAL2.
8. Resultado del escaneo de secretos.
9. Limitaciones productivas reales, sin marketing ni afirmaciones no demostradas.
10. Instrucciones puntuales para que un usuario humano pruebe la aplicación sin consultar archivos de credenciales o MFA.

Si queda un solo criterio obligatorio sin demostrar, informar el porcentaje y el bloqueo exacto; no usar “100%”.
