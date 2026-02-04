---
title: Gestion des Politiques
---

# Gestion des Politiques

Apprenez comment découvrir, gérer et mettre à jour les politiques dans InfraGuard.

## Lister les Politiques

### Lister Toutes les Politiques

Voir toutes les règles et packs disponibles :

```bash
infraguard policy list
```

Cela affiche :
- Toutes les règles intégrées
- Tous les packs de conformité
- Politiques personnalisées (le cas échéant)

### Filtrer par Fournisseur

Actuellement, InfraGuard supporte les politiques Aliyun. Les versions futures supporteront des fournisseurs supplémentaires.

## Détails des Politiques

### Obtenir des Informations sur une Règle

Voir des informations détaillées sur une règle spécifique :

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

La sortie inclut :
- ID et nom de la règle
- Niveau de sévérité
- Description
- Raison de l'échec
- Recommandation
- Types de ressources affectés

### Obtenir des Informations sur un Pack

Voir les détails d'un pack de conformité :

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

La sortie inclut :
- ID et nom du pack
- Description
- Liste des règles incluses

## Mettre à Jour les Politiques

InfraGuard inclut des politiques intégrées, mais vous pouvez également télécharger la dernière bibliothèque de politiques :

```bash
infraguard policy update
```

Cela télécharge les politiques vers `~/.infraguard/policies/`, qui a la priorité sur les politiques intégrées.

## Nettoyer les Politiques

Pour supprimer les politiques téléchargées de votre répertoire utilisateur :

```bash
infraguard policy clean
```

Cette commande :
- Supprime toutes les politiques de `~/.infraguard/policies/`
- Demande confirmation par défaut
- N'affecte pas les politiques intégrées (elles restent disponibles)
- N'affecte pas les politiques de l'espace de travail dans `.infraguard/policies/`

### Nettoyage Forcé (Sans Confirmation)

Pour les scripts ou environnements non interactifs :

```bash
infraguard policy clean --force
# ou
infraguard policy clean -f
```

### Priorité de Chargement des Politiques

InfraGuard charge les politiques depuis trois sources avec la priorité suivante (du plus élevé au plus bas) :

1. **Politiques locales de l'espace de travail** : `.infraguard/policies/` (relatif au répertoire de travail actuel)
2. **Politiques locales utilisateur** : `~/.infraguard/policies/`
3. **Politiques intégrées** : Intégrées dans le binaire (secours)

Les politiques avec le même ID provenant de sources de priorité plus élevée remplacent celles de priorité plus faible. Cela permet :
- **Politiques spécifiques au projet** : Définir des règles personnalisées dans `.infraguard/policies/` qui sont sous contrôle de version avec votre projet
- **Personnalisations utilisateur** : Remplacer les politiques intégrées globalement via `~/.infraguard/policies/`
- **Secours transparent** : Les politiques intégrées fonctionnent sans configuration

## Valider les Politiques Personnalisées

Avant d'utiliser des politiques personnalisées, validez-les :

```bash
infraguard policy validate ./my-custom-rule.rego
```

Cela vérifie :
- Syntaxe Rego
- Métadonnées requises (`rule_meta` ou `pack_meta`)
- Structure appropriée de la règle deny

### Options de Validation

```bash
# Valider un seul fichier
infraguard policy validate rule.rego

# Valider un répertoire
infraguard policy validate ./policies/

# Spécifier la langue de sortie
infraguard policy validate rule.rego --lang fr
```

## Formater les Politiques

Formatez vos fichiers de politiques en utilisant le formateur OPA :

```bash
# Afficher la sortie formatée
infraguard policy format rule.rego

# Écrire les modifications dans le fichier
infraguard policy format rule.rego --write

# Afficher le diff des modifications
infraguard policy format rule.rego --diff
```

## Organisation des Politiques

### Politiques Intégrées

Situées dans le binaire sous :
- `policies/aliyun/rules/` - Règles individuelles
- `policies/aliyun/packs/` - Packs de conformité
- `policies/aliyun/lib/` - Bibliothèques auxiliaires

### Politiques Personnalisées

#### Politiques Locales de l'Espace de Travail (Spécifiques au Projet)

Stockez les politiques spécifiques au projet dans votre répertoire de projet :
- `.infraguard/policies/<provider>/rules/` - Règles spécifiques au projet
- `.infraguard/policies/<provider>/packs/` - Packs spécifiques au projet
- `.infraguard/policies/<provider>/lib/` - Bibliothèques auxiliaires spécifiques au projet

Ces politiques sont automatiquement chargées lors de l'exécution des commandes InfraGuard depuis le répertoire du projet et peuvent être sous contrôle de version avec vos modèles IaC.

#### Politiques Locales Utilisateur (Globales)

Stockez les politiques personnalisées globales dans votre répertoire home :
- `~/.infraguard/policies/<provider>/rules/` - Règles personnalisées globales
- `~/.infraguard/policies/<provider>/packs/` - Packs personnalisés globaux
- `~/.infraguard/policies/<provider>/lib/` - Bibliothèques auxiliaires personnalisées globales

Ces politiques sont disponibles pour tous les projets et peuvent remplacer les politiques intégrées.
