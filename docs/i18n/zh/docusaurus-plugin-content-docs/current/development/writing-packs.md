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

## 位置

包可以放置在：
- 工作区本地：`.infraguard/policies/{provider}/packs/`
- 用户本地：`~/.infraguard/policies/{provider}/packs/`

有关策略加载优先级的详细信息，请参阅[策略目录结构](./policy-directory)。

## 下一步

- 查看[策略验证](./policy-validation)
- 了解[策略目录结构](./policy-directory)
- 探索[辅助函数](./helper-functions)
