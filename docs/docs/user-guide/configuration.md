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
infraguard config set lang zh  # Chinese
infraguard config set lang en  # English
```

## Configuration File

The configuration file is located at `~/.infraguard/config.yaml`:

```yaml
lang: zh
```

You can edit this file directly if preferred.

