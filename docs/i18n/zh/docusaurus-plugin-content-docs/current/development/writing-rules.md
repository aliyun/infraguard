---
title: 编写规则
---

# 编写自定义规则

了解如何为 InfraGuard 编写自定义合规规则。

## 规则结构

规则使用 Rego（Open Policy Agent 语言）编写，具有以下结构：

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

## 关键组件

### 包名

必须遵循格式：`infraguard.rules.<provider>.<rule_name_snake_case>`

**注意**：在包名中使用下划线，而不是连字符。

### 规则元数据

必需字段：
- `id`: 规则标识符（kebab-case）
- `name`: 显示名称（i18n 映射）
- `severity`: `high`、`medium` 或 `low`
- `description`: 规则检查的内容
- `reason`: 失败的原因
- `recommendation`: 如何修复
- `resource_types`: 受影响的资源类型（可选）

### Deny 规则

必须返回包含以下内容的结果：
- `id`: 规则 ID
- `resource_id`: 模板中的资源名称
- `violation_path`: 问题属性的路径
- `meta`: 严重性、原因、建议

## 辅助函数

有关可用的实用函数，请参阅[辅助函数](./helper-functions)。

## 验证

始终验证您的规则：

```bash
infraguard policy validate my-rule.rego
```

## 下一步

- 查看[策略验证](./policy-validation)
- 学习[编写包](./writing-packs)
- 了解[策略目录结构](./policy-directory)
- 探索[辅助函数](./helper-functions)

