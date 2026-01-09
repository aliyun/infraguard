---
title: 编写包
---

# 编写合规包

包将相关规则组合在一起，以便更轻松地管理策略。

## 包结构

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

## 关键点

- 包：`infraguard.packs.<provider>.<pack_name_snake_case>`
- 使用短规则 ID（不带 `rule:<provider>:` 前缀）
- 为名称和描述提供 i18n

有关更多详细信息，请参阅[项目文档](https://github.com/aliyun/infraguard)。

