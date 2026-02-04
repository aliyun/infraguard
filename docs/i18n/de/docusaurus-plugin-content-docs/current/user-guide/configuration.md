---
title: Konfiguration
---

# Konfiguration

InfraGuard speichert die Konfiguration in `~/.infraguard/config.yaml`.

## Konfiguration Verwalten

### Wert Setzen

```bash
infraguard config set lang de
```

### Wert Abrufen

```bash
infraguard config get lang
```

### Alle Einstellungen Auflisten

```bash
infraguard config list
```

### Wert Entfernen

```bash
infraguard config unset lang
```

## Verfügbare Einstellungen

### Sprache (`lang`)

Legen Sie die Standard-Ausgabesprache fest:

```bash
infraguard config set lang zh  # Chinese (中文)
infraguard config set lang en  # English (Englisch)
infraguard config set lang es  # Spanish (Spanisch)
infraguard config set lang fr  # French (Französisch)
infraguard config set lang de  # German (Deutsch)
infraguard config set lang ja  # Japanese (日本語)
infraguard config set lang pt  # Portuguese (Portugiesisch)
```

InfraGuard unterstützt 7 Sprachen: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. Der Standardwert wird automatisch basierend auf Ihrer Systemeinstellung erkannt.

## Konfigurationsdatei

Die Konfigurationsdatei befindet sich unter `~/.infraguard/config.yaml`:

```yaml
lang: de
```

Sie können diese Datei direkt bearbeiten, wenn Sie möchten.
