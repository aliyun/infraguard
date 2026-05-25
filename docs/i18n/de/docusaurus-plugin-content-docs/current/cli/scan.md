---
title: infraguard scan
---

# infraguard scan

ROS-Vorlagen und Terraform-Konfigurationen auf Compliance-Verstöße scannen.

## Synopsis

```bash
infraguard scan <template> -p <policy> [flags]
```

## Argumente

- `<template>`: Pfad zu einer ROS-Vorlagendatei, Terraform `.tf`-Datei oder einem Verzeichnis mit unterstützten Vorlagen (erforderlich, Positionsargument)

## Flags

| Flag | Typ | Beschreibung |
|------|-----|--------------|
| `-p, --policy <id>` | string | Anzuwendende Richtlinie (kann mehrfach verwendet werden, erforderlich) |
| `--format <format>` | string | Ausgabeformat (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Ausgabedateipfad |
| `--lang <lang>` | string | Ausgabesprache (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`) |
| `-m, --mode <mode>` | string | Scan-Modus: `static` für lokale Analyse oder `preview` für ROS PreviewStack API (Standard: `static`) |
| `-i, --input <value>` | string | Parameterwerte im Format `key=value`, JSON-Format oder Dateipfad (kann mehrfach angegeben werden) |

## Beispiele

```bash
# Mit einer Regel scannen
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Ein Terraform-Projekt scannen
infraguard scan ./terraform -p pack:aliyun:quick-start-compliance-pack

# Eine Terraform-Datei scannen und Variablen übergeben
infraguard scan main.tf -p rule:aliyun:ecs-instance-no-public-ip --input terraform.tfvars

# Mit einem Paket scannen
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# Mit Wildcard-Muster scannen (alle Regeln)
infraguard scan template.yaml -p "rule:*"

# Mit Wildcard-Muster scannen (alle ECS-Regeln)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# HTML-Bericht generieren
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# Scannen mit Preview-Modus
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview

# Scannen mit Vorlagenparametern
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --input InstanceType=ecs.c6.large --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd

# Preview-Modus mit Parametern aus JSON-Datei
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview --input parameters.json
```

## Exit-Codes

- `0`: Keine Verstöße gefunden
- `1`: Verstöße gefunden
- `2`: Verstöße mit hoher Schwere gefunden

Für weitere Details siehe [Vorlagen Scannen](../user-guide/scanning-templates).
