---
title: Écrire des Packs
---

# Écrire des Packs de Conformité

Les packs regroupent des règles connexes pour faciliter la gestion des politiques.

## Structure de Pack

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

## Points Clés

- Package : `infraguard.packs.<provider>.<pack_name_snake_case>`
- Utilisez des IDs de règle courts (sans préfixe `rule:<provider>:`)
- Fournissez i18n pour le nom et la description

## Emplacement

Les packs peuvent être placés dans :
- Workspace-local : `.infraguard/policies/{provider}/packs/`
- Utilisateur-local : `~/.infraguard/policies/{provider}/packs/`

Voir [Structure de Répertoire de Politiques](./policy-directory) pour les détails sur la priorité de chargement des politiques.

## Prochaines Étapes

- Voir [Validation de Politiques](./policy-validation)
- Apprenez-en plus sur [Structure de Répertoire de Politiques](./policy-directory)
- Explorez [Fonctions Auxiliaires](./helper-functions)
