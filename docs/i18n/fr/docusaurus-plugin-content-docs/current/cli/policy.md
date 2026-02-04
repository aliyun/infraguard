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
