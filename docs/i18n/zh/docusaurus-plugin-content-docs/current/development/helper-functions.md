---
title: 辅助函数
---

# 辅助函数

InfraGuard 提供辅助函数以简化策略编写。

使用以下方式导入它们：
```rego
import data.infraguard.helpers
```

## 可用函数

| 函数 | 描述 |
|----------|-------------|
| `resources_by_type(type)` | 获取某种类型的所有资源作为 `{name: resource}` 映射 |
| `resource_names_by_type(type)` | 获取某种类型的所有资源名称作为列表 |
| `count_resources_by_type(type)` | 计算某种类型的资源数量 |
| `resource_exists(type)` | 检查资源类型是否存在 |
| `has_property(resource, prop)` | 检查属性是否存在且不为 null |
| `get_property(resource, prop, default)` | 获取属性，带默认值 |
| `is_true(v)` / `is_false(v)` | 检查布尔值（处理字符串 "true"/"false"） |
| `is_public_cidr(cidr)` | 检查 CIDR 是否为 `0.0.0.0/0` 或 `::/0` |
| `includes(list, elem)` | 检查元素是否在列表中 |

## 示例

```rego
# 获取所有 ECS 实例
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # 检查逻辑在这里
}

# 检查属性是否存在
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # 违规逻辑
}

# 检查公共 CIDR
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # 违规逻辑
}
```

有关更多示例，请参阅[编写规则](./writing-rules)。

