---
title: infraguard policy
---

# infraguard policy

Gestionar políticas de cumplimiento.

## Subcomandos

### list

Listar todas las políticas disponibles:
```bash
infraguard policy list
```

### get

Obtener detalles de una política específica:
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Actualizar la biblioteca de políticas:
```bash
infraguard policy update
```

### new

Generar una nueva regla personalizada (esqueleto Rego + fixtures de prueba):
```bash
# Generar una regla para ROS y Terraform
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# Generar un esqueleto de paquete de cumplimiento
infraguard policy new --pack my-team-baseline
```

Los archivos generados se ubican bajo `--dir` (predeterminado `./policies`) y pueden usarse directamente con `infraguard scan -p ./policies <template>` y `infraguard policy test`. Consulte [Crear Reglas Personalizadas](../development/scaffolding-rules).

| Flag | Descripción | Predeterminado |
| --- | --- | --- |
| `--iac` | IaC objetivo: `ros`, `terraform`, o `both` | `both` |
| `--severity` | `high`, `medium`, o `low` | `medium` |
| `--resource-type` | Tipo de recurso ROS (repetible) | — |
| `--tf-resource-type` | Tipo de recurso Terraform (repetible) | — |
| `--dir` | Directorio raíz de salida | `./policies` |
| `--name-en` / `--name-zh` | Nombre de la regla | ID de la regla |
| `--desc-en` / `--desc-zh` | Descripción de la regla | `TODO` |
| `--no-test` | No generar fixtures de prueba | `false` |
| `--force` | Sobrescribir archivos existentes | `false` |
| `--pack` | Generar un esqueleto de paquete con el ID indicado | — |

### test

Ejecutar pruebas de comportamiento para las reglas usando sus fixtures:
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

Para cada regla, se evalúan las fixtures bajo `<dir>/testdata/aliyun/rules/<rule>/`: las fixtures `compliant` no deben producir **ninguna** violación de la regla, y las fixtures `violation` deben producir **al menos una**. El código de salida es `0` cuando todos los casos pasan, `1` en caso de fallo, y `2` cuando no se encuentran fixtures (a menos que se use `--allow-empty`). Consulte [Probar Reglas](../development/scaffolding-rules).

| Flag | Descripción | Predeterminado |
| --- | --- | --- |
| `--dir` | Directorio raíz que contiene `rules/` y `testdata/` | `./policies` |
| `--rule` | Probar solo el ID de regla indicado (repetible) | todas |
| `--iac` | IaC a probar: `ros`, `terraform`, o `both` | `both` |
| `--format` | Formato de salida: `table` o `json` | `table` |
| `--allow-empty` | Finalizar con `0` aunque no se encuentren fixtures | `false` |

### validate

Validar políticas personalizadas:
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang es
```

### format

Formatear archivos de políticas:
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

Limpiar el directorio de políticas del usuario:
```bash
infraguard policy clean              # Modo interactivo con confirmación
infraguard policy clean --force      # Omitir confirmación
infraguard policy clean -f           # Flag corto
```

Elimina todas las políticas de `~/.infraguard/policies/`. No afecta las políticas integradas ni las políticas del espacio de trabajo.

Para más detalles, consulte [Gestión de Políticas](../user-guide/managing-policies).
