---
title: Configuration
---

# Configuration

InfraGuard stores configuration in `~/.infraguard/config.yaml`.

## Managing Configuration

### Set a Value

```bash
infraguard config set lang zh
```

### Get a Value

```bash
infraguard config get lang
```

### List All Settings

```bash
infraguard config list
```

### Unset a Value

```bash
infraguard config unset lang
```

## Available Settings

### Language (`lang`)

Set the default output language:

```bash
infraguard config set lang zh  # Chinese (中文)
infraguard config set lang en  # English
infraguard config set lang es  # Spanish (Español)
infraguard config set lang fr  # French (Français)
infraguard config set lang de  # German (Deutsch)
infraguard config set lang ja  # Japanese (日本語)
infraguard config set lang pt  # Portuguese (Português)
```

InfraGuard supports 7 languages: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. The default is auto-detected based on your system locale.

## Configuration File

The configuration file is located at `~/.infraguard/config.yaml`:

```yaml
lang: zh
```

You can edit this file directly if preferred.

