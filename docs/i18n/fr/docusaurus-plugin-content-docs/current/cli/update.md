---
title: infraguard update
---

# infraguard update

Mettre à jour InfraGuard CLI vers la dernière version ou une version spécifique.

## Synopsis

```bash
infraguard update [flags]
```

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `--check` | boolean | Vérifier les mises à jour sans installer |
| `-f`, `--force` | boolean | Forcer la mise à jour même si la version est actuelle |
| `--version` | string | Mettre à jour vers une version spécifique |

## Exemples

### Vérifier les Mises à Jour

Vérifier si une nouvelle version est disponible sans installer :

```bash
infraguard update --check
```

Sortie :
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
✓ A new version is available: 0.5.0
```

### Mettre à Jour vers la Dernière Version

Mettre à jour vers la dernière version disponible :

```bash
infraguard update
```

Sortie :
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
→ Downloading version 0.5.0...
Downloaded 39.5 MiB / 39.5 MiB (100.0%)
✓ Successfully updated to version 0.5.0!
```

### Mettre à Jour vers une Version Spécifique

Installer une version spécifique :

```bash
infraguard update --version 0.5.0
```

### Réinstaller Forcément la Version Actuelle

Réinstaller la version actuelle :

```bash
infraguard update --force
# ou
infraguard update -f
```
