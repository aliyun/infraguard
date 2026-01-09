---
title: Welcome to InfraGuard
sidebar_label: Introduction
---

# InfraGuard

**Policy Defined. Infrastructure Secured.**

**Infrastructure as Code (IaC) compliance pre-check CLI** for Alibaba Cloud ROS templates.

Evaluate your ROS YAML/JSON templates against security and compliance policies **before deployment**.

## What is InfraGuard?

InfraGuard is a command-line tool that helps you ensure your infrastructure code meets security and compliance standards before deploying to production. It uses Open Policy Agent (OPA) and Rego policies to evaluate your templates.

## Key Features

- <img src="/img/features/validation.svg" width="20" height="20" style={{verticalAlign: 'middle', marginRight: '4px'}} /> **Pre-deployment Validation** - Catch compliance issues before they reach production
- <img src="/img/features/rules.svg" width="20" height="20" style={{verticalAlign: 'middle', marginRight: '4px'}} /> **Policy Packs** - Pre-built compliance packs (MLPS, ISO 27001, PCI-DSS, etc.)
- <img src="/img/features/i18n.svg" width="20" height="20" style={{verticalAlign: 'middle', marginRight: '4px'}} /> **Internationalization** - Full support for English and Chinese
- <img src="/img/features/formats.svg" width="20" height="20" style={{verticalAlign: 'middle', marginRight: '4px'}} /> **Multiple Output Formats** - Table, JSON, and HTML reports
- <img src="/img/features/extensible.svg" width="20" height="20" style={{verticalAlign: 'middle', marginRight: '4px'}} /> **Extensible** - Write custom policies in Rego
- <img src="/img/features/fast.svg" width="20" height="20" style={{verticalAlign: 'middle', marginRight: '4px'}} /> **Fast** - Built in Go for speed and efficiency

## Supported Providers

- **Aliyun (Alibaba Cloud)** - 78+ rules and 34+ compliance packs

## Quick Example

```bash
# Scan a template with a compliance pack
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Scan with specific rules
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Generate HTML report
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## Get Started

Ready to improve your infrastructure compliance? Check out our [Quick Start Guide](./getting-started/quick-start) to begin.

## Policy Library

Browse our comprehensive [Policy Reference](./policies/aliyun/rules) to see all available rules and compliance packs.
