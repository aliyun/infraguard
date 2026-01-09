---
title: 策略验证
---

# 策略验证

在使用自定义策略之前验证它们。

## 验证命令

```bash
infraguard policy validate <path>
```

## 验证内容

- Rego 语法
- 必需的元数据（`rule_meta` 或 `pack_meta`）
- 正确的 deny 规则结构
- i18n 字符串格式

## 示例

```bash
# 验证单个文件
infraguard policy validate rule.rego

# 验证目录
infraguard policy validate ./policies/

# 使用语言选项
infraguard policy validate rule.rego --lang zh
```

有关更多信息，请参阅[管理策略](../user-guide/managing-policies)。

