# Modelo de costos

La plataforma no cobra a sus usuarios y no monetiza datos. “Gratis” no significa infraestructura, energía, correo, backups y operación sin costo.

Los importes siguientes son **rangos presupuestarios ilustrativos en USD**, no cotizaciones ni precios vigentes garantizados. Deben reemplazarse por cotizaciones de la jurisdicción y proveedores aprobados.

## Fórmula

```text
costo mensual = cómputo/energía
              + almacenamiento primario
              + backups fuera del host
              + correo transaccional
              + dominio/TLS
              + observabilidad
              + tiempo de operación y soporte
              + reserva de recuperación/renovación
```

## Escenarios iniciales

| Escenario | Infraestructura mensual ilustrativa | Trabajo humano | Límites |
|---|---:|---|---|
| Equipo existente/autohospedado | USD 10–70 | 4–12 h/mes | depende de energía, Internet, copias externas y reemplazo de hardware |
| VPS pequeño con copias externas | USD 30–150 | 4–10 h/mes | no implica alta disponibilidad; residencia/proveedor por validar |
| Operación redundante/gestionada | USD 180–700+ | 8–20 h/mes | precio cambia según base, objetos, WORM, correo y soporte |

No incluir tiempo humano produciría una cifra engañosa. Aplicar la tarifa/valor horario local acordado.

## Autohospedado local

Rubros:

- energía: `consumo medio kW × 24 × 30 × tarifa kWh`;
- desgaste/reemplazo del equipo amortizado;
- UPS y conectividad;
- disco principal y copia cifrada en otro dispositivo/ubicación;
- dominio y acceso TLS si habrá usuarios remotos;
- horas de actualización, monitoreo, recuperación y soporte.

Un servidor local único no satisface por sí solo continuidad ni backup. La copia debe salir del mismo disco y, para desastres físicos, de la misma ubicación.

## Sensibilidad por tenant

Database-per-tenant aumenta bases, conexiones, migraciones, backups y verificaciones. Controlar:

- límite/poda de pools;
- tamaño real por padrón/fotos/reportes;
- frecuencia y retención de backups;
- número de restauraciones de ensayo;
- almacenamiento de objetos y egreso;
- correos de invitación/alerta;
- soporte por iglesia.

## Costos no incluidos todavía

- auditoría criptográfica y pentest;
- asesoría jurídica/privacidad;
- revisión/traducción institucional ES/FR;
- accesibilidad con usuarios y dispositivos;
- permisos de marca/materiales si generaran costos;
- hardware HSM/KMS o WORM de producción;
- alta disponibilidad y recuperación geográfica.

## Proceso de aprobación

1. Confirmar número de tenants, usuarios, padrón y retención.
2. Medir demo/carga real.
3. Solicitar al menos dos cotizaciones comparables por rubro material.
4. Documentar residencia, contrato, salida y eliminación.
5. Añadir 20–30 % de reserva operativa.
6. Revisar trimestralmente uso y costo, sin monetizar datos.
