---
title: Structure de Répertoire de Politiques
---

# Structure de Répertoire de Politiques

InfraGuard supporte plusieurs sources de politiques avec un système de priorité clair pour charger les politiques.

## Structure de Répertoire

### Structure de Répertoire de Politiques Standard

Les politiques suivent une structure de répertoire d'abord par fournisseur :

```
{policy-root}/
├── {provider}/
│   ├── rules/
│   │   ├── rule1.rego            # Règles individuelles
│   │   └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # Packs de conformité
│       └── pack2.rego
```

**Exemple :**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── metadata-ros-composer-check.rego
│   │   ├── metadata-templatetags-check.rego
│   │   ├── parameter-sensitive-noecho-check.rego
│   │   └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

## Priorité de Chargement des Politiques

InfraGuard charge les politiques depuis plusieurs sources avec la priorité suivante (du plus élevé au plus bas) :

1. **Politiques locales de l'espace de travail** : `.infraguard/policies/` (répertoire de travail actuel)
2. **Politiques locales utilisateur** : `~/.infraguard/policies/` (répertoire home de l'utilisateur)
3. **Politiques intégrées** : Intégrées dans le binaire

Les politiques avec le même ID provenant de sources de priorité plus élevée remplaceront celles de sources de priorité plus faible.

## Politiques Locales de l'Espace de Travail

Les politiques locales de l'espace de travail sont stockées dans le répertoire `.infraguard/policies/` dans votre répertoire de travail actuel. C'est l'emplacement de priorité la plus élevée et idéal pour :

- Règles et packs personnalisés spécifiques au projet
- Remplacer les politiques intégrées pour des projets spécifiques
- Tester de nouvelles politiques avant de les promouvoir à utilisateur-local ou intégrées

### Utiliser les Politiques de l'Espace de Travail

1. Créez la structure de répertoires :

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. Ajoutez vos règles ou packs personnalisés aux répertoires appropriés

3. Listez les politiques disponibles :

```bash
infraguard policy list
```

Vos politiques de l'espace de travail apparaîtront avec le format d'ID : `rule:myprovider:rule-name` ou `pack:myprovider:pack-name`

4. Utilisez-les dans les scans :

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## Politiques Locales Utilisateur

Les politiques locales utilisateur sont stockées dans `~/.infraguard/policies/` dans votre répertoire home. Ces politiques sont disponibles dans tous les projets pour votre compte utilisateur.

## Génération d'ID

InfraGuard génère automatiquement les IDs de politiques basés sur la structure de répertoires :

- **Règles** : `rule:{provider}:{rule-id}`
- **Packs** : `pack:{provider}:{pack-id}`

Où `{provider}` est dérivé du nom du répertoire parent (p. ex., `solution`, `aliyun`, `custom`).

## Prochaines Étapes

- Apprenez à [Écrire des Règles](./writing-rules)
- Apprenez à [Écrire des Packs](./writing-packs)
- Voir [Validation de Politiques](./policy-validation)
