---
title: infraguard policy
---

# infraguard policy

Gérer les politiques de conformité.

## Sous-commandes

### list

Lister toutes les politiques disponibles :
```bash
infraguard policy list
```

### get

Obtenir les détails d'une politique spécifique :
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Mettre à jour la bibliothèque de politiques :
```bash
infraguard policy update
```

### new

Générer une nouvelle règle personnalisée (squelette Rego + fixtures de test) :
```bash
# Générer une règle pour ROS et Terraform
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# Générer un squelette de pack de conformité
infraguard policy new --pack my-team-baseline
```

Les fichiers générés se trouvent sous `--dir` (par défaut `./policies`) et peuvent être utilisés directement avec `infraguard scan -p ./policies <template>` et `infraguard policy test`. Consultez [Rédaction de Règles Personnalisées](../development/scaffolding-rules).

| Flag | Description | Défaut |
| --- | --- | --- |
| `--iac` | IaC cible : `ros`, `terraform`, ou `both` | `both` |
| `--severity` | `high`, `medium`, ou `low` | `medium` |
| `--resource-type` | Type de ressource ROS (répétable) | — |
| `--tf-resource-type` | Type de ressource Terraform (répétable) | — |
| `--dir` | Répertoire racine de sortie | `./policies` |
| `--name-en` / `--name-zh` | Nom de la règle | ID de la règle |
| `--desc-en` / `--desc-zh` | Description de la règle | `TODO` |
| `--no-test` | Ne pas générer de fixtures de test | `false` |
| `--force` | Écraser les fichiers existants | `false` |
| `--pack` | Générer un squelette de pack avec l'ID donné | — |

### test

Exécuter les tests de comportement des règles à l'aide de leurs fixtures :
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

Pour chaque règle, les fixtures sous `<dir>/testdata/aliyun/rules/<rule>/` sont évaluées : les fixtures `compliant` ne doivent produire **aucune** violation de la règle, et les fixtures `violation` doivent en produire **au moins une**. Le code de sortie est `0` lorsque tous les cas passent, `1` en cas d'échec, et `2` lorsqu'aucune fixture n'est trouvée (sauf si `--allow-empty`). Consultez [Tester les Règles](../development/scaffolding-rules).

| Flag | Description | Défaut |
| --- | --- | --- |
| `--dir` | Répertoire racine contenant `rules/` et `testdata/` | `./policies` |
| `--rule` | Tester uniquement l'ID de règle donné (répétable) | toutes |
| `--iac` | IaC à tester : `ros`, `terraform`, ou `both` | `both` |
| `--format` | Format de sortie : `table` ou `json` | `table` |
| `--allow-empty` | Sortir avec `0` même si aucune fixture n'est trouvée | `false` |

### validate

Valider les politiques personnalisées :
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang fr
```

### format

Formater les fichiers de politiques :
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

Nettoyer le répertoire de politiques utilisateur :
```bash
infraguard policy clean              # Mode interactif avec confirmation
infraguard policy clean --force      # Ignorer la confirmation
infraguard policy clean -f           # Flag court
```

Supprime toutes les politiques de `~/.infraguard/policies/`. N'affecte pas les politiques intégrées ni les politiques de l'espace de travail.

Pour plus de détails, consultez [Gestion des Politiques](../user-guide/managing-policies).
