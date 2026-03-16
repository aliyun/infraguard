---
title: Intégration Éditeur
---

# Intégration Éditeur

InfraGuard fournit une intégration éditeur via un serveur Language Server Protocol (LSP) intégré et une extension VS Code, offrant un support d'édition intelligent pour les modèles ROS.

## Extension VS Code

### Installation

Installez l'extension **InfraGuard** depuis le [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=aliyun.infraguard), ou recherchez "InfraGuard" dans le panneau Extensions de VS Code.

L'extension nécessite que le CLI `infraguard` soit installé et disponible dans votre PATH. Voir [Installation](../getting-started/installation) pour plus de détails.

### Fonctionnalités

#### Complétion Automatique

Complétions contextuelles sur toute la structure du modèle :

- **Types de ressources** — Tous les identifiants de types de ressources ALIYUN::*
- **Propriétés** — Propriétés des ressources avec informations de type, propriétés requises priorisées
- **Fonctions intrinsèques** — `Fn::Join`, `Fn::Sub`, `Fn::Select`, et plus
- **Cibles Ref/GetAtt** — Références aux paramètres, ressources et leurs attributs
- **Définitions de paramètres** — Type, Default, AllowedValues et autres propriétés de paramètres
- **Sections de niveau supérieur** — ROSTemplateFormatVersion, Parameters, Resources, Outputs, etc.

Lorsque vous saisissez un type de ressource, un bloc `Properties` avec toutes les clés requises est inséré automatiquement.

#### Diagnostics en Temps Réel

Valide votre modèle au fur et à mesure de la saisie :

- `ROSTemplateFormatVersion` manquant ou invalide
- Types de ressources inconnus
- Propriétés requises manquantes
- Incompatibilités de type pour les valeurs des propriétés
- Définitions de paramètres invalides
- Clés YAML dupliquées
- Clés inconnues avec des suggestions « Vouliez-vous dire ? »

#### Documentation au Survol

Survolez les éléments pour voir la documentation contextuelle :

- **Types de ressources** — Description et lien vers la documentation officielle
- **Propriétés** — Type, contraintes, requis ou optionnel, comportement de mise à jour
- **Fonctions intrinsèques** — Syntaxe et exemples d'utilisation

#### Coloration Syntaxique

Coloration syntaxique améliorée pour les éléments spécifiques à ROS :

- `!Ref`, `Fn::Join` et autres fonctions intrinsèques
- Identifiants de types de ressources `ALIYUN::*::*`

### Types de Fichiers Pris en Charge

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | Reconnu automatiquement comme modèles ROS |
| `*.ros.json` | Reconnu automatiquement comme modèles ROS |
| `*.yaml` / `*.json` | Détecté via `ROSTemplateFormatVersion` dans le contenu |

### Commandes

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | Récupérer le schéma le plus récent des types de ressources depuis l'API ROS |

### Mise à Jour du Schéma ROS

L'extension inclut un schéma intégré pour les types de ressources ROS. Pour le mettre à jour avec les définitions les plus récentes :

1. Ouvrez la Palette de commandes (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Exécutez **InfraGuard: Update ROS Schema**

Cela nécessite que les identifiants Alibaba Cloud soient configurés. Voir [`infraguard schema update`](../cli/schema) pour la configuration des identifiants.

## Serveur LSP

Le serveur LSP peut être intégré à tout éditeur prenant en charge le Language Server Protocol.

### Démarrer le Serveur

```bash
infraguard lsp
```

Le serveur communique via stdio (entrée/sortie standard).

### Configuration de l'Éditeur

Pour les éditeurs autres que VS Code, configurez le client LSP pour :

1. Démarrer le serveur avec `infraguard lsp`
2. Utiliser stdio comme transport
3. Associer aux types de fichiers YAML et JSON

Voir [`infraguard lsp`](../cli/lsp) pour plus de détails.
