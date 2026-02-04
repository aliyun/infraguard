---
title: Hilfsfunktionen
---

# Hilfsfunktionen

InfraGuard bietet Hilfsfunktionen, um das Schreiben von Richtlinien zu vereinfachen.

Importieren Sie sie mit:
```rego
import data.infraguard.helpers
```

## Verfügbare Funktionen

| Funktion | Beschreibung |
|----------|--------------|
| `resources_by_type(type)` | Alle Ressourcen eines Typs als `{name: resource}`-Map abrufen |
| `resource_names_by_type(type)` | Alle Ressourcennamen eines Typs als Liste abrufen |
| `count_resources_by_type(type)` | Ressourcen eines Typs zählen |
| `resource_exists(type)` | Prüfen, ob Ressourcentyp existiert |
| `has_property(resource, prop)` | Prüfen, ob Eigenschaft existiert und nicht null ist |
| `get_property(resource, prop, default)` | Eigenschaft mit Standardwert abrufen |
| `is_true(v)` / `is_false(v)` | Booleschen Wert prüfen (behandelt String "true"/"false") |
| `is_public_cidr(cidr)` | Prüfen, ob CIDR `0.0.0.0/0` oder `::/0` ist |
| `includes(list, elem)` | Prüfen, ob Element in Liste ist |

## Beispiele

```rego
# Alle ECS-Instanzen abrufen
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Prüflogik hier
}

# Prüfen, ob Eigenschaft existiert
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # Verstoßlogik
}

# Öffentliches CIDR prüfen
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # Verstoßlogik
}
```

Für weitere Beispiele siehe [Regeln Schreiben](./writing-rules).
