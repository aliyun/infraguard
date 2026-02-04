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

## Policy as Code

InfraGuard embraces the **Policy as Code** approach - treating compliance policies as first-class code artifacts that can be versioned, tested, and automated.

- **Version Control** - Store policies in Git alongside your infrastructure code. Track changes, review history, and roll back when needed.
- **Automated Testing** - Write unit tests for your policies using sample templates. Ensure policies work correctly before applying them to production.
- **Code Review** - Apply the same peer review process to policy changes as you do for application code. Catch issues early through collaboration.
- **CI/CD Integration** - Integrate policy checks into your CI/CD pipeline. Automatically validate every infrastructure change against compliance requirements.
- **Reusability** - Compose individual rules into compliance packs. Share policies across teams and projects to maintain consistency.
- **Declarative** - Define *what* compliance means using Rego's declarative syntax, not *how* to check it. Focus on the outcome, not the implementation.

## Key Features

- **Pre-deployment Validation** - Catch compliance issues before they reach production
- **Policy Packs** - Pre-built compliance packs (MLPS, ISO 27001, PCI-DSS, etc.)
- **Internationalization** - Full support for 7 languages (English, Chinese, Spanish, French, German, Japanese, Portuguese)
- **Multiple Output Formats** - Table, JSON, and HTML reports
- **Extensible** - Write custom policies in Rego
- **Fast** - Built in Go for speed and efficiency

## Supported Providers

- **Aliyun (Alibaba Cloud)** - Hundreds of rules and dozens of compliance packs

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
