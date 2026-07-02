---
title: infraguard scan
---

# infraguard scan

Scan ROS templates and Terraform configurations for compliance violations.

## Synopsis

```bash
infraguard scan <template> -p <policy> [flags]
```

## Arguments

- `<template>`: Path to a ROS template file, Terraform `.tf` file, or a directory containing supported templates (required, positional argument)

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `-p, --policy <id>` | string | Policy to apply (can be used multiple times, required) |
| `--format <format>` | string | Output format (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Output file path |
| `--lang <lang>` | string | Output language (`en` or `zh`) |
| `-m, --mode <mode>` | string | Scan mode: `static` for local analysis or `preview` for ROS PreviewStack API (default: `static`) |
| `-i, --input <value>` | string | Parameter values in `key=value`, JSON format, or file path (can be specified multiple times) |
| `--severity <level>` | string | Filter catalog rules by severity (`high`, `medium`, `low`); repeat the flag or use comma-separated values |
| `--waivers <path>` | string | Path to waiver file (default: auto-detect `.infraguard/waivers.yaml`) |
| `--no-waivers` | bool | Ignore all waivers (inline comments and waiver file) |
| `--show-waived` | bool | Show waived violations instead of hiding them |
| `--fail-on-expired` | bool | Treat expired waivers as real violations (default: `true`) |

## Waivers

Violations can be suppressed with a reason via inline comments or a central
`.infraguard/waivers.yaml` file. Active waivers are hidden (and counted in the
summary); expired waivers reappear and fail the build by default. See the
[Waivers guide](../user-guide/waivers) and [infraguard waiver](./waiver).

## Examples

```bash
# Scan with a rule
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Scan a Terraform project
infraguard scan ./terraform -p pack:aliyun:quick-start-compliance-pack

# Scan a Terraform file and pass variables
infraguard scan main.tf -p rule:aliyun:ecs-instance-no-public-ip --input terraform.tfvars

# Scan with a pack
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# Scan with a pack and only run high/medium severity rules
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --severity high --severity medium

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
