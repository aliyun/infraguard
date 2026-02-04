---
title: Pakete Schreiben
---

# Compliance-Pakete Schreiben

Pakete gruppieren verwandte Regeln zusammen, um die Richtlinienverwaltung zu erleichtern.

## Paketstruktur

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

## Wichtige Punkte

- Paket: `infraguard.packs.<provider>.<pack_name_snake_case>`
- Verwenden Sie kurze Regel-IDs (ohne Präfix `rule:<provider>:`)
- Stellen Sie i18n für Name und Beschreibung bereit

## Speicherort

Pakete können platziert werden in:
- Arbeitsbereichslokal: `.infraguard/policies/{provider}/packs/`
- Benutzerlokal: `~/.infraguard/policies/{provider}/packs/`

Siehe [Richtlinienverzeichnisstruktur](./policy-directory) für Details zur Richtlinienladepriorität.

## Nächste Schritte

- Siehe [Richtlinienvalidierung](./policy-validation)
- Erfahren Sie mehr über [Richtlinienverzeichnisstruktur](./policy-directory)
- Erkunden Sie [Hilfsfunktionen](./helper-functions)
