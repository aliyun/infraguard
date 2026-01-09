---
title: Writing Rules
---

# Writing Custom Rules

Learn how to write custom compliance rules for InfraGuard.

## Rule Structure

Rules are written in Rego (Open Policy Agent language) with the following structure:

```rego
package infraguard.rules.aliyun.my_custom_rule

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "my-custom-rule",
    "name": {
        "en": "My Custom Rule",
        "zh": "我的自定义规则",
    },
    "severity": "high",
    "description": {
        "en": "Checks for custom compliance requirement",
        "zh": "检查自定义合规要求",
    },
    "reason": {
        "en": "Resource does not meet requirement",
        "zh": "资源不符合要求",
    },
    "recommendation": {
        "en": "Configure resource properly",
        "zh": "正确配置资源",
    },
    "resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Your compliance logic here
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SomeProperty"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    # Your compliance check logic
}
```

## Key Components

### Package Name

Must follow format: `infraguard.rules.<provider>.<rule_name_snake_case>`

**Note**: Use underscores, not hyphens in package names.

### Rule Metadata

Required fields:
- `id`: Rule identifier (kebab-case)
- `name`: Display name (i18n map)
- `severity`: `high`, `medium`, or `low`
- `description`: What the rule checks
- `reason`: Why it failed
- `recommendation`: How to fix
- `resource_types`: Affected resource types (optional)

### Deny Rule

Must return results with:
- `id`: Rule ID
- `resource_id`: Resource name from template
- `violation_path`: Path to problematic property
- `meta`: Severity, reason, recommendation

## Helper Functions

See [Helper Functions](./helper-functions) for available utility functions.

## Validation

Always validate your rules:

```bash
infraguard policy validate my-rule.rego
```

## Next Steps

- Explore [Helper Functions](./helper-functions)
- Learn to [Write Packs](./writing-packs)
- See [Policy Validation](./policy-validation)

