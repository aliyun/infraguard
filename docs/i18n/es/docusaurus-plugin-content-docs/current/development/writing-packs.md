---
title: Escribir Paquetes
---

# Escribir Paquetes de Cumplimiento

Los paquetes agrupan reglas relacionadas para facilitar la gestión de políticas.

## Estructura de Paquete

```rego
package infraguard.packs.aliyun.my_pack

import rego.v1

pack_meta := {
    "id": "my-pack",
    "name": {
        "en": "My Compliance Pack",
        "zh": "我的合规包",
    },
    "description": {
        "en": "Collection of related rules",
        "zh": "相关规则集合",
    },
    "rules": [
        "rule-short-id-1",
        "rule-short-id-2",
        "rule-short-id-3",
    ],
}
```

## Puntos Clave

- Paquete: `infraguard.packs.<provider>.<pack_name_snake_case>`
- Use IDs de regla cortos (sin prefijo `rule:<provider>:`)
- Proporcione i18n para nombre y descripción

## Ubicación

Los paquetes pueden colocarse en:
- Workspace-local: `.infraguard/policies/{provider}/packs/`
- Usuario-local: `~/.infraguard/policies/{provider}/packs/`

Consulte [Estructura de Directorio de Políticas](./policy-directory) para detalles sobre la prioridad de carga de políticas.

## Próximos Pasos

- Vea [Validación de Políticas](./policy-validation)
- Aprenda sobre [Estructura de Directorio de Políticas](./policy-directory)
- Explore [Funciones Auxiliares](./helper-functions)
