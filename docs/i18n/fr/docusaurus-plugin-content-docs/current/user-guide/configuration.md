---
title: Configuration
---

# Configuration

InfraGuard stocke la configuration dans `~/.infraguard/config.yaml`.

## Gestion de la Configuration

### Définir une Valeur

```bash
infraguard config set lang fr
```

### Obtenir une Valeur

```bash
infraguard config get lang
```

### Lister Tous les Paramètres

```bash
infraguard config list
```

### Supprimer une Valeur

```bash
infraguard config unset lang
```

## Paramètres Disponibles

### Langue (`lang`)

Définissez la langue de sortie par défaut :

```bash
infraguard config set lang zh  # Chinese (中文)
infraguard config set lang en  # English (Anglais)
infraguard config set lang es  # Spanish (Espagnol)
infraguard config set lang fr  # French (Français)
infraguard config set lang de  # German (Allemand)
infraguard config set lang ja  # Japanese (日本語)
infraguard config set lang pt  # Portuguese (Portugais)
```

InfraGuard supporte 7 langues : `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. La valeur par défaut est détectée automatiquement en fonction de votre paramètre régional système.

## Fichier de Configuration

Le fichier de configuration se trouve dans `~/.infraguard/config.yaml` :

```yaml
lang: fr
```

Vous pouvez éditer ce fichier directement si vous le souhaitez.
