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
