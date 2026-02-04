---
title: Escribir Reglas
---

# Escribir Reglas Personalizadas

Aprenda cómo escribir reglas de cumplimiento personalizadas para InfraGuard.

## Estructura de Regla

Las reglas se escriben en Rego (lenguaje Open Policy Agent) con la siguiente estructura:

```rego
package infraguard.rules.aliyun.my_custom_rule

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "my-custom-rule",
    "name": {
        "en": "My Custom Rule",
        "zh": "我的自定义规则",
    },
    "severity": "high",
    "description": {
        "en": "Checks for custom compliance requirement",
        "zh": "检查自定义合规要求",
    },
    "reason": {
        "en": "Resource does not meet requirement",
        "zh": "资源不符合要求",
    },
    "recommendation": {
        "en": "Configure resource properly",
        "zh": "正确配置资源",
    },
    "resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Su lógica de cumplimiento aquí
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SomeProperty"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    # Su lógica de verificación de cumplimiento aquí
}
```

## Componentes Clave

### Nombre del Paquete

Debe seguir el formato: `infraguard.rules.<provider>.<rule_name_snake_case>`

**Nota**: Use guiones bajos, no guiones en los nombres de paquetes.

### Metadatos de Regla

Campos requeridos:
- `id`: Identificador de regla (kebab-case)
- `name`: Nombre para mostrar (mapa i18n)
- `severity`: `high`, `medium`, o `low`
- `description`: Qué verifica la regla
- `reason`: Por qué falló
- `recommendation`: Cómo corregir
- `resource_types`: Tipos de recursos afectados (opcional)

### Regla Deny

Debe devolver resultados con:
- `id`: ID de regla
- `resource_id`: Nombre del recurso desde la plantilla
- `violation_path`: Ruta a la propiedad problemática
- `meta`: Severidad, razón, recomendación

## Funciones Auxiliares

Consulte [Funciones Auxiliares](./helper-functions) para funciones de utilidad disponibles.

## Validación

Siempre valide sus reglas:

```bash
infraguard policy validate my-rule.rego
```

## Depuración de Reglas

Use declaraciones print para depurar sus reglas durante el desarrollo:

```rego
deny contains result if {
    print("Checking resource:", name)
    print("Resource properties:", object.keys(resource.Properties))
    # Su lógica aquí
}
```

Consulte [Depuración de Políticas](./debugging-policies) para técnicas completas de depuración.

## Próximos Pasos

- Aprenda [Depuración de Políticas](./debugging-policies)
- Vea [Validación de Políticas](./policy-validation)
- Aprenda a [Escribir Paquetes](./writing-packs)
- Aprenda sobre [Estructura de Directorio de Políticas](./policy-directory)
- Explore [Funciones Auxiliares](./helper-functions)
