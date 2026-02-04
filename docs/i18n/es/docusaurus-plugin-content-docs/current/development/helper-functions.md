---
title: Funciones Auxiliares
---

# Funciones Auxiliares

InfraGuard proporciona funciones auxiliares para simplificar la escritura de políticas.

Impórtelas con:
```rego
import data.infraguard.helpers
```

## Funciones Disponibles

| Función | Descripción |
|---------|-------------|
| `resources_by_type(type)` | Obtener todos los recursos de un tipo como mapa `{name: resource}` |
| `resource_names_by_type(type)` | Obtener todos los nombres de recursos de un tipo como lista |
| `count_resources_by_type(type)` | Contar recursos de un tipo |
| `resource_exists(type)` | Verificar si existe el tipo de recurso |
| `has_property(resource, prop)` | Verificar si la propiedad existe y no es null |
| `get_property(resource, prop, default)` | Obtener propiedad con valor predeterminado |
| `is_true(v)` / `is_false(v)` | Verificar booleano (maneja string "true"/"false") |
| `is_public_cidr(cidr)` | Verificar si CIDR es `0.0.0.0/0` o `::/0` |
| `includes(list, elem)` | Verificar si el elemento está en la lista |

## Ejemplos

```rego
# Obtener todas las instancias ECS
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Lógica de verificación aquí
}

# Verificar si la propiedad existe
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # Lógica de violación
}

# Verificar CIDR público
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # Lógica de violación
}
```

Para más ejemplos, consulte [Escribir Reglas](./writing-rules).
