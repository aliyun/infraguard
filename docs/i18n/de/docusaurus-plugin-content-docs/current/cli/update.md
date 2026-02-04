---
title: infraguard update
---

# infraguard update

InfraGuard CLI auf die neueste Version oder eine bestimmte Version aktualisieren.

## Synopsis

```bash
infraguard update [flags]
```

## Flags

| Flag | Typ | Beschreibung |
|------|-----|--------------|
| `--check` | boolean | Nach Updates suchen ohne Installation |
| `-f`, `--force` | boolean | Update erzwingen, auch wenn Version aktuell ist |
| `--version` | string | Auf eine bestimmte Version aktualisieren |

## Beispiele

### Nach Updates Suchen

Prüfen, ob eine neue Version verfügbar ist, ohne zu installieren:

```bash
infraguard update --check
```

Ausgabe:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
✓ A new version is available: 0.5.0
```

### Auf Neueste Version Aktualisieren

Auf die neueste verfügbare Version aktualisieren:

```bash
infraguard update
```

Ausgabe:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
→ Downloading version 0.5.0...
Downloaded 39.5 MiB / 39.5 MiB (100.0%)
✓ Successfully updated to version 0.5.0!
```

### Auf Bestimmte Version Aktualisieren

Eine bestimmte Version installieren:

```bash
infraguard update --version 0.5.0
```

### Aktuelle Version Erzwingen Neuinstallieren

Die aktuelle Version neuinstallieren:

```bash
infraguard update --force
# oder
infraguard update -f
```
