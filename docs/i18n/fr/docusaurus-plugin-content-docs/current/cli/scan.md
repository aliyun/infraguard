---
title: infraguard scan
---

# infraguard scan

Scanner les modèles ROS pour détecter les violations de conformité.

## Synopsis

```bash
infraguard scan <template> -p <policy> [flags]
```

## Arguments

- `<template>`: Chemin vers le fichier de modèle ROS (requis, argument positionnel)

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `-p, --policy <id>` | string | Politique à appliquer (peut être utilisée plusieurs fois, requis) |
| `--format <format>` | string | Format de sortie (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Chemin du fichier de sortie |
| `--lang <lang>` | string | Langue de sortie (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`) |
| `-m, --mode <mode>` | string | Mode de scan : `static` pour analyse locale ou `preview` pour ROS PreviewStack API (par défaut : `static`) |
| `-i, --input <value>` | string | Valeurs de paramètres au format `key=value`, JSON, ou chemin de fichier (peut être spécifié plusieurs fois) |

## Exemples

```bash
# Scanner avec une règle
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Scanner avec un pack
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# Scanner avec motif générique (toutes les règles)
infraguard scan template.yaml -p "rule:*"

# Scanner avec motif générique (toutes les règles ECS)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Générer un rapport HTML
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# Scanner en utilisant le mode preview
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview

# Scanner avec paramètres de modèle
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --input InstanceType=ecs.c6.large --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd

# Mode preview avec paramètres depuis fichier JSON
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview --input parameters.json
```

## Codes de Sortie

- `0`: Aucune violation trouvée
- `1`: Violations trouvées
- `2`: Violations de haute sévérité trouvées

Pour plus de détails, consultez [Scanner les Modèles](../user-guide/scanning-templates).
