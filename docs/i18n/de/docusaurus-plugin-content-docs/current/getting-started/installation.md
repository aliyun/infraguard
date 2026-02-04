---
title: Installation
---

# Installation

## Mit go install (Empfohlen)

Der einfachste Weg, InfraGuard zu installieren, ist die Verwendung von `go install`:

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Dies lädt herunter, kompiliert und installiert die `infraguard`-Binärdatei in Ihr `$GOPATH/bin`-Verzeichnis (oder `$HOME/go/bin`, wenn `GOPATH` nicht gesetzt ist).

Stellen Sie sicher, dass Ihr Go-Bin-Verzeichnis in Ihrem PATH ist:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Installation Überprüfen

```bash
infraguard version
```

Sie sollten die Versionsinformationen angezeigt sehen.

## Vorkompilierte Binärdateien Herunterladen

Sie können vorkompilierte Binärdateien von [GitHub Releases](https://github.com/aliyun/infraguard/releases) herunterladen.

### Verfügbare Plattformen

| Plattform | Architektur | Dateiname |
|-----------|-------------|-----------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### Installationsschritte

1. Laden Sie die entsprechende Binärdatei für Ihre Plattform von der [Releases-Seite](https://github.com/aliyun/infraguard/releases) herunter

2. Machen Sie die Binärdatei ausführbar (Linux/macOS):

```bash
chmod +x infraguard-*
```

3. Verschieben Sie sie in ein Verzeichnis in Ihrem PATH:

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# Oder für benutzerspezifische Installation
mv infraguard-* ~/bin/infraguard
```

4. Überprüfen Sie die Installation:

```bash
infraguard version
```

## Aus dem Quellcode Kompilieren (Optional)

Wenn Sie den Code ändern müssen oder es vorziehen, aus dem Quellcode zu kompilieren:

### Voraussetzungen

- **Go 1.24.6 oder höher**
- **Git**
- **Make**

### Schritte

```bash
# Repository klonen
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# Binärdatei erstellen
make build

# Optional in Ihren PATH installieren
sudo cp infraguard /usr/local/bin/
```

## Nächste Schritte

Jetzt, da Sie InfraGuard installiert haben, fahren Sie mit dem [Schnellstart-Leitfaden](./quick-start) fort, um zu lernen, wie Sie es verwenden.
