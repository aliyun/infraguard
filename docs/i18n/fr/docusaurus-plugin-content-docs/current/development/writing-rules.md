---
title: Écrire des Règles
---

# Écrire des Règles Personnalisées

Apprenez à écrire des règles de conformité personnalisées pour InfraGuard.

## Structure de Règle

Les règles sont écrites en Rego (langage Open Policy Agent) avec la structure suivante :

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
    # Votre logique de conformité ici
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
    # Votre logique de vérification de conformité ici
}
```

## Composants Clés

### Nom du Package

Doit suivre le format : `infraguard.rules.<provider>.<rule_name_snake_case>`

**Note** : Utilisez des underscores, pas des tirets dans les noms de packages.

### Métadonnées de Règle

Champs requis :
- `id`: Identifiant de règle (kebab-case)
- `name`: Nom d'affichage (carte i18n)
- `severity`: `high`, `medium`, ou `low`
- `description`: Ce que la règle vérifie
- `reason`: Pourquoi elle a échoué
- `recommendation`: Comment corriger
- `resource_types`: Types de ressources affectés (optionnel)

### Règle Deny

Doit retourner des résultats avec :
- `id`: ID de règle
- `resource_id`: Nom de la ressource depuis le modèle
- `violation_path`: Chemin vers la propriété problématique
- `meta`: Sévérité, raison, recommandation

## Fonctions Auxiliaires

Voir [Fonctions Auxiliaires](./helper-functions) pour les fonctions utilitaires disponibles.

## Validation

Validez toujours vos règles :

```bash
infraguard policy validate my-rule.rego
```

## Débogage de Règles

Utilisez des instructions print pour déboguer vos règles pendant le développement :

```rego
deny contains result if {
    print("Checking resource:", name)
    print("Resource properties:", object.keys(resource.Properties))
    # Votre logique ici
}
```

Voir [Débogage de Politiques](./debugging-policies) pour des techniques complètes de débogage.

## Prochaines Étapes

- Apprenez [Débogage de Politiques](./debugging-policies)
- Voir [Validation de Politiques](./policy-validation)
- Apprenez à [Écrire des Packs](./writing-packs)
- Apprenez-en plus sur [Structure de Répertoire de Politiques](./policy-directory)
- Explorez [Fonctions Auxiliaires](./helper-functions)
