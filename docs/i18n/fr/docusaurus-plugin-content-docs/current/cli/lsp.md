---
title: infraguard lsp
---

# infraguard lsp

Démarrer le serveur du protocole Language Server Protocol (LSP) ROS pour l'intégration avec les éditeurs.

## Synopsis

```bash
infraguard lsp [flags]
```

## Description

La commande `lsp` démarre un serveur du protocole Language Server Protocol (LSP) qui communique via les entrées/sorties standard (stdio). Elle fournit un support d'édition intelligent pour les modèles ROS dans des éditeurs comme VS Code, incluant :

- **Saisie semi-automatique** — Types de ressources, propriétés, fonctions intrinsèques, cibles Ref/GetAtt
- **Diagnostics en temps réel** — Version du format, types de ressources, propriétés requises, incompatibilités de type
- **Documentation au survol** — Descriptions, informations de type, contraintes pour les ressources et propriétés

Le serveur LSP prend en charge les formats de modèle YAML et JSON.

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `--stdio` | bool | Utiliser le transport stdio (par défaut, accepté pour la compatibilité avec les éditeurs) |

## Exemples

### Démarrer le Serveur LSP

```bash
infraguard lsp
```

### Démarrer avec le Flag stdio Explicite

```bash
infraguard lsp --stdio
```

## Intégration de l'Éditeur

Le serveur LSP est généralement démarré automatiquement par les extensions d'éditeur. Pour VS Code, installez l'[extension InfraGuard](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard) qui gère le cycle de vie du LSP.

Pour plus de détails, consultez [Intégration de l'Éditeur](../user-guide/editor-integration).

## Codes de Sortie

- `0`: Le serveur s'est terminé normalement
