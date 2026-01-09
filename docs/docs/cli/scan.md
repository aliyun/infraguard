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

- `-p, --policy <id>`: Policy to apply (can be used multiple times, required)
- `--format <format>`: Output format (`table`, `json`, `html`)
- `-o, --output <file>`: Output file path
- `--lang <lang>`: Output language (`en` or `zh`)

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
```

## Exit Codes

- `0`: No violations found
- `1`: Violations found
- `2`: High severity violations found

For more details, see [Scanning Templates](../user-guide/scanning-templates).

