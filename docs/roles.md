# Roles y permisos

Fuente de contrato actual: `packages/domain/src/permissions.ts`.

## Principios

- Denegación predeterminada y mínimo privilegio.
- Un rol local no concede poderes globales.
- Nadie delega un permiso que no posee como delegable.
- Ser administrador, presidente o secretario no concede voto; el derecho depende del snapshot de electores.
- Una asignación de rol no concede por sí sola claves E2EE.
- UI y API derivan la consola de acceso de las mismas capacidades devueltas por el servidor; la API sigue siendo autoritativa y las mutaciones exigen sesión MFA y CSRF.
- Una persona con membresías en varias iglesias recibe autorizaciones independientes.

## Perfiles iniciales

| Perfil | Facultades predeterminadas | Exclusiones importantes |
|---|---|---|
| Administrador global | aprovisionamiento, suspensión, salud y seguridad global | no padrón, boletas, notas o claves de iglesias |
| Administrador de iglesia | tenant, padrón, comité, catálogo, ciclos, conducción y reportes | no voto automático; no contenido de boleta individual |
| Presidente/coordinador | conducir fases, revisar candidatos, participación nominal y resultados autorizados | no voto automático; no rol global |
| Secretario | preparar/conducir, registrar seguimiento y exportar según delegación | no voto automático; notas solo con permiso adicional |
| Miembro de junta | consultar, proponer, votar y ver agregados autorizados | no participación nominal de otros ni resultados parciales |
| Custodio | material de escrutinio, recuento y publicación delegada | no administración general ni padrón completo por defecto |
| Auditor | organigrama, reportes, agregados y auditoría autorizados | solo lectura; no preferencias individuales |

Demo materializa cinco identidades separadas. Administración posee `CHURCH_ADMIN` y, por pertenecer al electorado sintético ya congelado, `COMMITTEE_MEMBER`; secretaría, integrante de comisión, custodia y auditoría poseen respectivamente `COMMITTEE_SECRETARY`, `COMMITTEE_MEMBER`, `TALLY_CUSTODIAN` y `AUDITOR`. Cada perfil tiene contraseña y MFA propios. Custodia usa sus llaves de dispositivo y no recibe la clave general de contenido tenant.

## Catálogo atómico

| Área | Permisos |
|---|---|
| Plataforma | `platform.tenant.provision`, `platform.tenant.suspend`, `platform.tenant.reactivate`, `platform.operation.read`, `platform.security.manage` |
| Tenant | `tenant.settings.manage` |
| Miembros | `member.read`, `member.manage`, `member.contact.read`, `member.contact.manage`, `member.eligibility.manage`, `member.photo.manage`, `member.import` |
| Comité/catálogo/ciclo | `committee.manage`, `catalog.manage`, `cycle.manage` |
| Resoluciones de flujo | `workflow.eligibility.resolve`, `linked-designation.record` |
| Propuestas | `proposal.open`, `proposal.close`, `proposal.submit` |
| Participación | `participation.nominal.read` |
| Depuración | `candidate.review` |
| Votación | `ballot.open`, `ballot.close`, `ballot.submit` |
| Escrutinio | `tally.custody`, `tally.recount`, `aggregate.publish`, `aggregate.read` |
| Resultado | `consent.record`, `congregational-decision.record` |
| Salidas | `organigram.read`, `report.read`, `report.export` |
| Sensibles | `private-note.read`, `audit.read`, `role.manage`, `recovery.activate` |

## Reglas de evaluación

1. Resolver sesión y tenant.
2. Verificar revocación, expiración y membresía.
3. Cargar bindings/versiones del tenant.
4. Comprobar permiso atómico.
5. Comprobar alcance del objeto, ciclo, ronda y audiencia.
6. Para votar/proponer, comprobar elector congelado y ausencia de recepción previa.
7. Para claves/contenido, comprobar además concesión criptográfica vigente.
8. Auditar la decisión sensible sin contenido secreto.

## Administración local implementada

`role.manage` permite listar permisos/capacidades, roles y bindings del tenant activo. Solo se pueden crear o editar códigos `LOCAL_*`; los roles de sistema son inmutables. El servidor rechaza permisos `platform.*`, permisos no poseídos como delegables, delegabilidad superior a la del actor, autoasignación y autorrevocación. Los bindings se conceden únicamente a membresías activas del mismo tenant y las versiones optimistas evitan sobrescrituras silenciosas. Crear, editar, conceder o revocar queda auditado; las sesiones de identidades afectadas se revocan para que el cambio sea efectivo sin conservar privilegios en caché.

El cambio explícito de tenant solo acepta una membresía propia activa, revoca la sesión anterior y rota cookie de sesión y CSRF. Antes de presentar el nuevo contexto, la web bloquea el vault, cancela consultas, elimina cachés y vuelve a cargar permisos. Entrar a la consola global aplica la misma frontera de memoria y conserva únicamente la sesión y consultas globales indispensables.

## Administración global implementada

La consola global lista estado operativo, cola/worker y activación sin consultar contenido, roles locales ni claves de tenant. Aprovisionar y suspender requieren permiso global específico, MFA y CSRF. La API ordinaria encola; un worker separado posee las credenciales administrativas. Un tenant real se mantiene `pending_activation` hasta disponer de una invitación inicial `CHURCH_ADMIN` de un solo uso. El bootstrap del primer administrador global crea una sesión `enrollment_only`, sin rol tenant ni concesión de clave, y bloquea todo privilegio hasta completar MFA.

## Guías operativas

- [Administrador global](guides/platform-administrator.md)
- [Administrador de iglesia](guides/church-administrator.md)
- [Secretario](guides/secretary.md)
- [Miembro de junta](guides/committee-member.md)

## Soporte

No existe impersonación silenciosa. Una concesión de soporte debe indicar tenant, operador, permisos, razón, inicio, caducidad y revocación, y no concede acceso retroactivo a boletas o claves.

## Validación y límites pendientes

- `role-access.spec.ts` recorrió en Chromium ES los límites UI/API de secretaría, integrante de comisión, custodia y auditoría. Formó parte del cierre integral actual de 25 etapas aprobadas más una sonda Firefox `accepted-optional`, 1.196/1.196 pruebas no Playwright y Playwright con 106 aprobadas, 54 exclusiones exactas permitidas y 0 fallos; esos totales agregados no equivalen a una certificación independiente del modelo de autorización.
- Revisión de permisos predeterminados por responsables de Ozama.
- El resto del fixture usa el administrador predeterminado; la matriz exhaustiva de cada perfil/acción en ES/EN/FR permanece pendiente.
- Las ceremonias de concesión criptográfica deben permanecer separadas de RBAC: asignar un rol nunca concede por sí solo una clave E2EE.
