---
title: Scanning Templates
---

# Scanning Templates

The `infraguard scan` command evaluates your ROS templates against compliance policies.

## Basic Usage

```bash
infraguard scan <template> -p <policy>
```

### Required Arguments

- `<template>`: Path to your ROS template file (YAML or JSON) - positional argument

### Required Flags

- `-p, --policy <id>`: Policy to apply (can be used multiple times)

### Optional Flags

- `--format <format>`: Output format (`table`, `json`, or `html`)
- `-o, --output <file>`: Output file path (for HTML and JSON formats)
- `--lang <lang>`: Output language (`en` or `zh`)

## Policy Types

You can scan with different types of policies:

### 1. Individual Rules

Scan with a specific compliance rule:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. Compliance Packs

Scan with a pre-defined compliance pack:

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. Wildcard Pattern Matching

Use wildcard patterns (`*`) to match multiple rules or packs:

**Match all rules:**
```bash
infraguard scan template.yaml -p "rule:*"
```

**Match rules by prefix:**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. Custom Policy Files

Scan with your own Rego policy file:

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. Policy Directories

Scan with all policies in a directory:

```bash
infraguard scan template.yaml -p ./my-policies/
```

## Multiple Policies

Apply multiple policies in a single scan:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## Output Formats

### Table Format (Default)

Displays results in a color-coded table:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Example output:

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### JSON Format

Machine-readable format for CI/CD integration:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

Output:

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### HTML Report

Interactive HTML report with filtering and search:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Open `report.html` in your browser for an interactive experience.

## Exit Codes

InfraGuard uses different exit codes to indicate scan results:

- `0`: No violations found
- `1`: Violations found
- `2`: High severity violations found

This is useful for CI/CD pipelines:

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "High severity violations found! Blocking deployment."
  exit 1
fi
```

## Examples

### Example 1: Security Audit

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### Example 2: Compliance Check

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang zh \
  --format json \
  -o compliance-report.json
```

### Example 3: CI/CD Integration

```bash
# In your CI/CD pipeline
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

## Tips

1. **Start with Quick Start Pack**: Use `pack:aliyun:quick-start-compliance-pack` for essential checks
2. **Use Multiple Packs**: Combine multiple packs for comprehensive coverage
3. **Save Reports**: Use HTML format for stakeholder reports, JSON for automation
4. **Set Language Once**: Use `infraguard config set lang zh` to avoid repeating `--lang` flag

## Next Steps

- Learn about [Managing Policies](./managing-policies)
- Explore [Output Formats](./output-formats) in detail
- Configure [Settings](./configuration)

