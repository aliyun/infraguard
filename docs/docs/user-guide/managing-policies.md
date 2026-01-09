---
title: Managing Policies
---

# Managing Policies

Learn how to discover, manage, and update policies in InfraGuard.

## Listing Policies

### List All Policies

View all available rules and packs:

```bash
infraguard policy list
```

This displays:
- All built-in rules
- All compliance packs
- Custom policies (if any)

### Filter by Provider

Currently, InfraGuard supports Aliyun policies. Future versions will support additional providers.

## Policy Details

### Get Rule Information

View detailed information about a specific rule:

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

Output includes:
- Rule ID and name
- Severity level
- Description
- Reason for failure
- Recommendation
- Affected resource types

### Get Pack Information

View compliance pack details:

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

Output includes:
- Pack ID and name
- Description
- List of included rules

## Updating Policies

InfraGuard includes embedded policies, but you can also download the latest policy library:

```bash
infraguard policy update
```

This downloads policies to `~/.infraguard/policies/`, which takes precedence over embedded policies.

### Policy Loading Priority

1. **User-local policies**: `~/.infraguard/policies/` (highest priority)
2. **Embedded policies**: Built into the binary (fallback)

## Validating Custom Policies

Before using custom policies, validate them:

```bash
infraguard policy validate ./my-custom-rule.rego
```

This checks:
- Rego syntax
- Required metadata (`rule_meta` or `pack_meta`)
- Proper deny rule structure

### Validation Options

```bash
# Validate a single file
infraguard policy validate rule.rego

# Validate a directory
infraguard policy validate ./policies/

# Specify output language
infraguard policy validate rule.rego --lang zh
```

## Formatting Policies

Format your policy files using OPA formatter:

```bash
# Show formatted output
infraguard policy format rule.rego

# Write changes back to file
infraguard policy format rule.rego --write

# Show diff of changes
infraguard policy format rule.rego --diff
```

## Policy Organization

### Built-in Policies

Located in the binary under:
- `policies/aliyun/rules/` - Individual rules
- `policies/aliyun/packs/` - Compliance packs
- `policies/aliyun/lib/` - Helper libraries

### Custom Policies

Store custom policies in:
- `~/.infraguard/policies/<provider>/rules/` - Custom rules
- `~/.infraguard/policies/<provider>/packs/` - Custom packs
- `~/.infraguard/policies/<provider>/lib/` - Custom helper libraries

## Common Compliance Packs

### Security & Best Practices

- `pack:aliyun:security-group-best-practice` - Security group configuration
- `pack:aliyun:resource-protection-best-practice` - Resource protection
- `pack:aliyun:multi-zone-architecture-best-practice` - High availability

### Compliance Standards

- `pack:aliyun:mlps-level-2-pre-check-compliance-pack` - MLPS Level 2
- `pack:aliyun:mlps-level-3-pre-check-compliance-pack` - MLPS Level 3
- `pack:aliyun:iso-27001-compliance` - ISO 27001
- `pack:aliyun:pci-dss-compliance` - PCI DSS
- `pack:aliyun:soc2-audit-compliance` - SOC 2

### Quick Start

- `pack:aliyun:quick-start-compliance-pack` - Essential security checks

## Tips

1. **Discover Policies**: Use `policy list` to explore available policies
2. **Start Small**: Begin with `quick-start-compliance-pack`
3. **Validate First**: Always validate custom policies before using them
4. **Keep Updated**: Regularly run `policy update` for latest rules

## Next Steps

- Learn about [Writing Rules](../development/writing-rules)
- Explore the [Policy Reference](../policies/aliyun/rules)
- Configure [Settings](./configuration)

