---
title: infraguard scan
---

# infraguard scan

Escanear plantillas ROS para detectar violaciones de cumplimiento.

## Sinopsis

```bash
infraguard scan <template> -p <policy> [flags]
```

## Argumentos

- `<template>`: Ruta al archivo de plantilla ROS (requerido, argumento posicional)

## Flags

| Flag | Tipo | Descripción |
|------|------|-------------|
| `-p, --policy <id>` | string | Política a aplicar (puede usarse múltiples veces, requerido) |
| `--format <format>` | string | Formato de salida (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Ruta del archivo de salida |
| `--lang <lang>` | string | Idioma de salida (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`) |
| `-m, --mode <mode>` | string | Modo de escaneo: `static` para análisis local o `preview` para ROS PreviewStack API (predeterminado: `static`) |
| `-i, --input <value>` | string | Valores de parámetros en formato `key=value`, JSON, o ruta de archivo (puede especificarse múltiples veces) |

## Ejemplos

```bash
# Escanear con una regla
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Escanear con un paquete
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# Escanear con patrón comodín (todas las reglas)
infraguard scan template.yaml -p "rule:*"

# Escanear con patrón comodín (todas las reglas ECS)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Generar informe HTML
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# Escanear usando modo preview
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview

# Escanear con parámetros de plantilla
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --input InstanceType=ecs.c6.large --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd

# Modo preview con parámetros desde archivo JSON
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview --input parameters.json
```

## Códigos de Salida

- `0`: No se encontraron violaciones
- `1`: Se encontraron violaciones
- `2`: Se encontraron violaciones de alta severidad

Para más detalles, consulte [Escaneo de Plantillas](../user-guide/scanning-templates).
