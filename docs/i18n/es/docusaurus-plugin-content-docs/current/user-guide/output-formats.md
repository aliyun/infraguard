---
title: Formatos de Salida
---

# Formatos de Salida

InfraGuard soporta tres formatos de salida: Tabla, JSON y HTML.

## Formato Tabla

Formato predeterminado con salida de consola codificada por colores. Mejor para uso interactivo.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## Formato JSON

Formato legible por máquina para automatización y pipelines CI/CD.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## Formato HTML

Informe interactivo con capacidades de filtrado y búsqueda.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Para ejemplos detallados, consulte [Escaneo de Plantillas](./scanning-templates).
