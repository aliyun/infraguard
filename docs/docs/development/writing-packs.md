---
title: Writing Packs
---

# Writing Compliance Packs

Packs group related rules together for easier policy management.

## Pack Structure

```rego
package infraguard.packs.aliyun.my_pack

import rego.v1

pack_meta := {
    "id": "my-pack",
    "name": {
        "en": "My Compliance Pack",
        "zh": "我的合规包",
    },
    "description": {
        "en": "Collection of related rules",
        "zh": "相关规则集合",
    },
    "rules": [
        "rule-short-id-1",
        "rule-short-id-2",
        "rule-short-id-3",
    ],
}
```

## Key Points

- Package: `infraguard.packs.<provider>.<pack_name_snake_case>`
- Use short rule IDs (without `rule:<provider>:` prefix)
- Provide i18n for name and description

## Location

Packs can be placed in:
- Workspace-local: `.infraguard/policies/{provider}/packs/`
- User-local: `~/.infraguard/policies/{provider}/packs/`

See [Policy Directory Structure](./policy-directory) for details on policy loading priority.

## Next Steps

- See [Policy Validation](./policy-validation)
- Learn about [Policy Directory Structure](./policy-directory)
- Explore [Helper Functions](./helper-functions)

