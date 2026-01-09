---
title: Policy Validation
---

# Policy Validation

Validate your custom policies before using them.

## Validation Command

```bash
infraguard policy validate <path>
```

## What Gets Validated

- Rego syntax
- Required metadata (`rule_meta` or `pack_meta`)
- Proper deny rule structure
- i18n string format

## Examples

```bash
# Validate a single file
infraguard policy validate rule.rego

# Validate a directory
infraguard policy validate ./policies/

# With language option
infraguard policy validate rule.rego --lang zh
```

For more information, see [Managing Policies](../user-guide/managing-policies).

