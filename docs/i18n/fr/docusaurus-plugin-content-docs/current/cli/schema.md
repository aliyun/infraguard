---
title: infraguard schema
---

# infraguard schema

Gérer le schéma des types de ressources ROS utilisé par le serveur LSP.

## Sous-commandes

### update

Récupérer le dernier schéma des types de ressources ROS depuis l'API ROS d'Alibaba Cloud et le sauvegarder localement :

```bash
infraguard schema update
```

## Description

La commande `schema` gère le schéma des types de ressources ROS que le serveur LSP utilise pour la saisie semi-automatique, la validation et la documentation au survol. Le schéma contient les définitions de tous les types de ressources ROS, leurs propriétés, types et contraintes.

### Prérequis

La sous-commande `schema update` nécessite des identifiants Alibaba Cloud. Configurez-les en utilisant l'une des options suivantes :

1. **Variables d'environnement** :
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **Configuration Aliyun CLI** :
   ```bash
   aliyun configure
   ```

## Exemples

### Mettre à jour le Schéma

```bash
infraguard schema update
```

Sortie :
```
Updating ROS resource type schema...
Schema updated successfully (350 resource types)
```

## Codes de Sortie

- `0` : Succès
- `1` : Erreur (p. ex., identifiants manquants, échec réseau)
