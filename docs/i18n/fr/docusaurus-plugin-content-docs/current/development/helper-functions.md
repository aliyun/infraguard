---
title: Fonctions Auxiliaires
---

# Fonctions Auxiliaires

InfraGuard fournit des fonctions auxiliaires pour simplifier l'écriture de politiques.

Importez-les avec :
```rego
import data.infraguard.helpers
```

## Fonctions Disponibles

| Fonction | Description |
|----------|-------------|
| `resources_by_type(type)` | Obtenir toutes les ressources d'un type comme carte `{name: resource}` |
| `resource_names_by_type(type)` | Obtenir tous les noms de ressources d'un type comme liste |
| `count_resources_by_type(type)` | Compter les ressources d'un type |
| `resource_exists(type)` | Vérifier si le type de ressource existe |
| `has_property(resource, prop)` | Vérifier si la propriété existe et n'est pas null |
| `get_property(resource, prop, default)` | Obtenir la propriété avec valeur par défaut |
| `is_true(v)` / `is_false(v)` | Vérifier booléen (gère string "true"/"false") |
| `is_public_cidr(cidr)` | Vérifier si CIDR est `0.0.0.0/0` ou `::/0` |
| `includes(list, elem)` | Vérifier si l'élément est dans la liste |

## Exemples

```rego
# Obtenir toutes les instances ECS
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Logique de vérification ici
}

# Vérifier si la propriété existe
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # Logique de violation
}

# Vérifier CIDR public
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # Logique de violation
}
```

Pour plus d'exemples, consultez [Écrire des Règles](./writing-rules).
