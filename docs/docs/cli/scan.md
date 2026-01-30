---
title: infraguard scan
---

# infraguard scan

Scan ROS templates for compliance violations.

## Synopsis

```bash
infraguard scan <template> -p <policy> [flags]
```

## Arguments

- `<template>`: Path to ROS template file (required, positional argument)

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `-p, --policy <id>` | string | Policy to apply (can be used multiple times, required) |
| `--format <format>` | string | Output format (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Output file path |
| `--lang <lang>` | string | Output language (`en` or `zh`) |
| `-m, --mode <mode>` | string | Scan mode: `static` for local analysis or `preview` for ROS PreviewStack API (default: `static`) |
| `-i, --input <value>` | string | Parameter values in `key=value`, JSON format, or file path (can be specified multiple times) |

## Examples

```bash
# Scan with a rule
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Scan with a pack
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# Scan with wildcard pattern (all rules)
infraguard scan template.yaml -p "rule:*"

# Scan with wildcard pattern (all ECS rules)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Generate HTML report
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# Scan using preview mode
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview

# Scan with template parameters
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --input InstanceType=ecs.c6.large --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd

# Preview mode with parameters from JSON file
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview --input parameters.json
```

## Exit Codes

- `0`: No violations found
- `1`: Violations found
- `2`: High severity violations found

For more details, see [Scanning Templates](../user-guide/scanning-templates).

