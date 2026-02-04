---
title: Quick Start
---

# Quick Start

This guide will help you get started with InfraGuard in just a few minutes.

## Step 1: Create a Sample ROS Template

Create a file named `template.yaml` with the following content:

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: Sample ECS instance

Resources:
  MyECS:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      ImageId: 'centos_7'
      InstanceType: 'ecs.t5-lc1m1.small'
      AllocatePublicIP: true
      SecurityGroupId: 'sg-xxxxx'
      VpcId: 'vpc-xxxxx'
      VSwitchId: 'vsw-xxxxx'
```

## Step 2: Run Your First Scan

Scan the template using a built-in rule:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

You should see output indicating that the ECS instance has a public IP allocated, which is a security concern.

## Step 3: Use a Compliance Pack

Instead of individual rules, you can scan with an entire compliance pack:

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## Step 4: Generate a Report

InfraGuard supports multiple output formats:

### Table Format (Default)

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### JSON Format

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### HTML Report

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Open `report.html` in your browser to view an interactive report.

## Step 5: List Available Policies

To see all available rules and packs:

```bash
# List all policies
infraguard policy list

# Get details about a specific rule
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# Get details about a compliance pack
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## Common Use Cases

### Scan with Multiple Policies

You can apply multiple policies in a single scan:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### Set Language Preference

InfraGuard supports 7 languages:

```bash
# Chinese output
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang zh

# English output
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# Other supported languages: es (Spanish), fr (French), de (German), ja (Japanese), pt (Portuguese)
```

You can also set the language permanently:

```bash
infraguard config set lang zh
```

Supported language codes: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. The default is auto-detected based on your system locale.

## Next Steps

- **Learn More**: Read the [User Guide](../user-guide/scanning-templates) for detailed information
- **Explore Policies**: Browse the [Policy Reference](../policies/aliyun/rules) to see all available rules and packs
- **Write Custom Policies**: Check out the [Development Guide](../development/writing-rules) to create your own rules

## Getting Help

If you encounter any issues:

1. Check the [FAQ](../faq) page
2. Review error messages carefully - they usually include helpful hints
3. Report issues on [GitHub](https://github.com/aliyun/infraguard/issues)

