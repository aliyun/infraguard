---
title: Escaneo de Plantillas
---

# Escaneo de Plantillas

El comando `infraguard scan` evalúa sus plantillas ROS contra políticas de cumplimiento.

## Uso Básico

```bash
infraguard scan <template> -p <policy>
```

### Argumentos Requeridos

- `<template>`: Ruta al archivo de plantilla ROS (YAML o JSON) - argumento posicional

### Flags Requeridos

- `-p, --policy <id>`: Política a aplicar (puede usarse múltiples veces)

### Flags Opcionales

- `--format <format>`: Formato de salida (`table`, `json`, o `html`)
- `-o, --output <file>`: Ruta del archivo de salida (para formatos HTML y JSON)
- `--lang <lang>`: Idioma de salida (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`)
- `-m, --mode <mode>`: Modo de escaneo (`static` para análisis local o `preview` para ROS PreviewStack API, predeterminado: `static`)
- `-i, --input <value>`: Valores de parámetros en formato `key=value`, JSON, o ruta de archivo (puede especificarse múltiples veces)

## Tipos de Políticas

Puede escanear con diferentes tipos de políticas:

### 1. Reglas Individuales

Escanear con una regla de cumplimiento específica:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. Paquetes de Cumplimiento

Escanear con un paquete de cumplimiento predefinido:

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. Coincidencia de Patrones Comodín

Use patrones comodín (`*`) para coincidir con múltiples reglas o paquetes:

**Coincidir con todas las reglas:**
```bash
infraguard scan template.yaml -p "rule:*"
```

**Coincidir reglas por prefijo:**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. Archivos de Políticas Personalizadas

Escanear con su propio archivo de política Rego:

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. Directorios de Políticas

Escanear con todas las políticas en un directorio:

```bash
infraguard scan template.yaml -p ./my-policies/
```

## Modos de Escaneo

InfraGuard soporta dos modos de escaneo:

### Modo Estático (Predeterminado)

Realiza análisis estático local de la plantilla sin requerir acceso al proveedor de nube:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode static
```

Este modo analiza la estructura de la plantilla y las configuraciones de recursos localmente. Es rápido y no requiere credenciales de nube, pero puede no soportar todas las características de ROS (consulte [Soporte de Características ROS](./ros-features)).

### Modo Preview

Usa la API ROS PreviewStack para validar plantillas con evaluación real del proveedor de nube:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview
```

El modo preview proporciona análisis más preciso para características que requieren evaluación en tiempo de ejecución (como `Fn::GetAtt`, `Fn::GetAZs`, etc.). Este modo requiere que las credenciales de ROS estén configuradas.

Para plantillas que usan características no soportadas por análisis estático, recomendamos usar `--mode preview` para resultados más precisos.

## Múltiples Políticas

Aplicar múltiples políticas en un solo escaneo:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## Formatos de Salida

### Formato Tabla (Predeterminado)

Muestra resultados en una tabla codificada por colores:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Salida de ejemplo:

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### Formato JSON

Formato legible por máquina para integración CI/CD:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

Salida:

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### Informe HTML

Informe HTML interactivo con filtrado y búsqueda:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Abra `report.html` en su navegador para una experiencia interactiva.

## Códigos de Salida

InfraGuard usa diferentes códigos de salida para indicar resultados del escaneo:

- `0`: No se encontraron violaciones
- `1`: Se encontraron violaciones
- `2`: Se encontraron violaciones de alta severidad

Esto es útil para pipelines CI/CD:

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "¡Se encontraron violaciones de alta severidad! Bloqueando despliegue."
  exit 1
fi
```

## Ejemplos

### Ejemplo 1: Auditoría de Seguridad

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### Ejemplo 2: Verificación de Cumplimiento

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang es \
  --format json \
  -o compliance-report.json
```

### Ejemplo 3: Integración CI/CD

```bash
# En su pipeline CI/CD
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

### Ejemplo 4: Modo Preview con Parámetros

Escanear usando modo preview con parámetros de plantilla:

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input InstanceType=ecs.c6.large \
  --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd
```

También puede proporcionar parámetros desde un archivo JSON:

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input parameters.json
```

## Consejos

1. **Comience con el Paquete de Inicio Rápido**: Use `pack:aliyun:quick-start-compliance-pack` para verificaciones esenciales
2. **Use Múltiples Paquetes**: Combine múltiples paquetes para cobertura integral
3. **Guarde Informes**: Use formato HTML para informes de partes interesadas, JSON para automatización
4. **Configure Idioma Una Vez**: Use `infraguard config set lang es` para evitar repetir el flag `--lang`

## Próximos Pasos

- Aprenda sobre [Gestión de Políticas](./managing-policies)
- Explore [Formatos de Salida](./output-formats) en detalle
- Configure [Configuración](./configuration)
