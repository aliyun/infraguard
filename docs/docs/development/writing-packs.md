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

For more details, see the [project documentation](https://github.com/aliyun/infraguard).

