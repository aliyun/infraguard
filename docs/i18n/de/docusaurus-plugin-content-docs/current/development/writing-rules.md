---
title: Regeln Schreiben
---

# Benutzerdefinierte Regeln Schreiben

Erfahren Sie, wie Sie benutzerdefinierte Compliance-Regeln für InfraGuard schreiben.

## Regelstruktur

Regeln werden in Rego (Open Policy Agent-Sprache) mit der folgenden Struktur geschrieben:

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
    # Ihre Compliance-Logik hier
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
    # Ihre Compliance-Prüflogik hier
}
```

## Hauptkomponenten

### Paketname

Muss dem Format folgen: `infraguard.rules.<provider>.<rule_name_snake_case>`

**Hinweis**: Verwenden Sie Unterstriche, keine Bindestriche in Paketnamen.

### Regelmetadaten

Erforderliche Felder:
- `id`: Regelkennung (kebab-case)
- `name`: Anzeigename (i18n-Map)
- `severity`: `high`, `medium` oder `low`
- `description`: Was die Regel prüft
- `reason`: Warum sie fehlgeschlagen ist
- `recommendation`: Wie man es behebt
- `resource_types`: Betroffene Ressourcentypen (optional)

### Deny-Regel

Muss Ergebnisse mit zurückgeben:
- `id`: Regel-ID
- `resource_id`: Ressourcenname aus der Vorlage
- `violation_path`: Pfad zur problematischen Eigenschaft
- `meta`: Schweregrad, Grund, Empfehlung

## Hilfsfunktionen

Siehe [Hilfsfunktionen](./helper-functions) für verfügbare Utility-Funktionen.

## Validierung

Validiere immer Ihre Regeln:

```bash
infraguard policy validate my-rule.rego
```

## Debugging von Regeln

Verwenden Sie print-Anweisungen, um Ihre Regeln während der Entwicklung zu debuggen:

```rego
deny contains result if {
    print("Checking resource:", name)
    print("Resource properties:", object.keys(resource.Properties))
    # Ihre Logik hier
}
```

Siehe [Debugging von Richtlinien](./debugging-policies) für umfassende Debugging-Techniken.

## Nächste Schritte

- Erfahren Sie [Debugging von Richtlinien](./debugging-policies)
- Siehe [Richtlinienvalidierung](./policy-validation)
- Lernen Sie [Pakete Schreiben](./writing-packs)
- Erfahren Sie mehr über [Richtlinienverzeichnisstruktur](./policy-directory)
- Erkunden Sie [Hilfsfunktionen](./helper-functions)
