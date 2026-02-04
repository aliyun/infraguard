---
title: Validation de Politiques
---

# Validation de Politiques

Validez vos politiques personnalisées avant de les utiliser.

## Commande de Validation

```bash
infraguard policy validate <path>
```

## Ce qui est Validé

- Syntaxe Rego
- Métadonnées requises (`rule_meta` ou `pack_meta`)
- Structure appropriée de la règle deny
- Format de chaîne i18n

## Exemples

```bash
# Valider un seul fichier
infraguard policy validate rule.rego

# Valider un répertoire
infraguard policy validate ./policies/

# Avec option de langue
infraguard policy validate rule.rego --lang fr
```

Pour plus d'informations, consultez [Gestion des Politiques](../user-guide/managing-policies).
