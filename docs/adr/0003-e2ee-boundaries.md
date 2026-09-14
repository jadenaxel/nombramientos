# ADR-0003 — E2EE por categorías y custodios explícitos

- Estado: Propuesta; auditoría criptográfica externa pendiente
- Fecha: 2026-09-10

## Contexto

TLS o cifrado de disco no ocultan contenido al servidor. Al mismo tiempo, la API necesita observar metadatos mínimos de fase, cuotas y recepción.

## Decisión

Cifrar en el cliente nombres, fotos, razones, notas, propuestas, boletas y documentos internos para destinatarios autorizados. Mantener identidad mínima, fase, tamaño, tiempos y recibos como metadatos de confianza explícitamente declarados. Las boletas se cifran hacia custodios y se cuentan en sus dispositivos después del cierre.

## Consecuencias

- Custodios autorizados pueden ver boletas durante el recuento; no se promete secreto frente a ellos.
- La pérdida de todas las claves y respaldos puede hacer irrecuperable el contenido.
- El servidor que entrega JavaScript y un dispositivo comprometido permanecen dentro del modelo de amenaza.
- Formatos, primitivas, autenticación de claves y recuperación deben ser revisados por especialistas antes de producción.
