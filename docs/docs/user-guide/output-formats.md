---
title: Output Formats
---

# Output Formats

InfraGuard supports three output formats: Table, JSON, and HTML.

## Table Format

Default format with color-coded console output. Best for interactive use.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## JSON Format

Machine-readable format for automation and CI/CD pipelines.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## HTML Format

Interactive report with filtering and search capabilities.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

For detailed examples, see [Scanning Templates](./scanning-templates).

