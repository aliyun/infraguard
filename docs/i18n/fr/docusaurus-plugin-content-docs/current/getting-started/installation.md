---
title: Installation
---

# Installation

## Utiliser go install (Recommandé)

La façon la plus simple d'installer InfraGuard est d'utiliser `go install` :

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Cela téléchargera, compilera et installera le binaire `infraguard` dans votre répertoire `$GOPATH/bin` (ou `$HOME/go/bin` si `GOPATH` n'est pas défini).

Assurez-vous que votre répertoire bin de Go est dans votre PATH :

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Vérifier l'Installation

```bash
infraguard version
```

Vous devriez voir les informations de version affichées.

## Télécharger les Binaires Précompilés

Vous pouvez télécharger les binaires précompilés depuis [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Plateformes Disponibles

| Plateforme | Architecture | Nom de Fichier |
|------------|--------------|----------------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### Étapes d'Installation

1. Téléchargez le binaire approprié pour votre plateforme depuis la [page Releases](https://github.com/aliyun/infraguard/releases)

2. Rendez le binaire exécutable (Linux/macOS) :

```bash
chmod +x infraguard-*
```

3. Déplacez-le vers un répertoire dans votre PATH :

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# Ou pour installation utilisateur uniquement
mv infraguard-* ~/bin/infraguard
```

4. Vérifiez l'installation :

```bash
infraguard version
```

## Compiler depuis le Code Source (Optionnel)

Si vous devez modifier le code ou préférez compiler depuis le code source :

### Prérequis

- **Go 1.24.6 ou ultérieur**
- **Git**
- **Make**

### Étapes

```bash
# Cloner le dépôt
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# Compiler le binaire
make build

# Optionnellement installer dans votre PATH
sudo cp infraguard /usr/local/bin/
```

## Prochaines Étapes

Maintenant que vous avez InfraGuard installé, passez au [Guide de Démarrage Rapide](./quick-start) pour apprendre à l'utiliser.
