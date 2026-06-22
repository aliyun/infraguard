---
title: infraguard scan
---

# infraguard scan

Escanear plantillas ROS y configuraciones Terraform para detectar violaciones de cumplimiento.

## Sinopsis

```bash
infraguard scan <template> -p <policy> [flags]
```

## Argumentos

- `<template>`: Ruta a un archivo de plantilla ROS, archivo Terraform `.tf`, o directorio con plantillas compatibles (requerido, argumento posicional)

## Flags

| Flag | Tipo | Descripción |
|------|------|-------------|
| `-p, --policy <id>` | string | Política a aplicar (puede usarse múltiples veces, requerido) |
| `--format <format>` | string | Formato de salida (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Ruta del archivo de salida |
| `--lang <lang>` | string | Idioma de salida (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`) |
| `-m, --mode <mode>` | string | Modo de escaneo: `static` para análisis local o `preview` para ROS PreviewStack API (predeterminado: `static`) |
| `-i, --input <value>` | string | Valores de parámetros en formato `key=value`, JSON, o ruta de archivo (puede especificarse múltiples veces) |
| `--waivers <path>` | string | Ruta al archivo de exenciones (predeterminado: autodetectar `.infraguard/waivers.yaml`) |
| `--no-waivers` | bool | Ignorar todas las exenciones (comentarios en línea y archivo de exenciones) |
| `--show-waived` | bool | Mostrar las violaciones exentas en lugar de ocultarlas |
| `--fail-on-expired` | bool | Tratar las exenciones caducadas como violaciones reales (predeterminado: `true`) |

## Exenciones

Las violaciones pueden suprimirse con un motivo mediante comentarios en línea o un
archivo central `.infraguard/waivers.yaml`. Las exenciones activas se ocultan (y se
contabilizan en el resumen); las exenciones caducadas reaparecen y hacen fallar la
compilación de forma predeterminada. Consulte la
[guía de Exenciones](../user-guide/waivers) e [infraguard waiver](./waiver).

## Ejemplos

```bash
# Escanear con una regla
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Escanear un proyecto Terraform
infraguard scan ./terraform -p pack:aliyun:quick-start-compliance-pack

# Escanear un archivo Terraform y pasar variables
infraguard scan main.tf -p rule:aliyun:ecs-instance-no-public-ip --input terraform.tfvars

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
