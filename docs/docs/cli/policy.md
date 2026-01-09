---
title: infraguard policy
---

# infraguard policy

Manage compliance policies.

## Subcommands

### list

List all available policies:
```bash
infraguard policy list
```

### get

Get details of a specific policy:
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Update the policy library:
```bash
infraguard policy update
```

### validate

Validate custom policies:
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang zh
```

### format

Format policy files:
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

For more details, see [Managing Policies](../user-guide/managing-policies).

