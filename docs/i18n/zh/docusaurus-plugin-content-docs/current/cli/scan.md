---
title: infraguard scan
---

# infraguard scan

扫描 ROS 模板以查找合规违规。

## 概要

```bash
infraguard scan <template> -p <policy> [选项]
```

## 参数

- `<template>`: ROS 模板文件路径（必需，位置参数）

## 选项

| 选项 | 类型 | 说明 |
|------|------|-------------|
| `-p, --policy <id>` | 字符串 | 要应用的策略（可多次使用，必需） |
| `--format <format>` | 字符串 | 输出格式（`table`、`json`、`html`） |
| `-o, --output <file>` | 字符串 | 输出文件路径 |
| `--lang <lang>` | 字符串 | 输出语言（`en` 或 `zh`） |

## 示例

```bash
# 使用规则扫描
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# 使用包扫描
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# 使用通配符模式扫描（所有规则）
infraguard scan template.yaml -p "rule:*"

# 使用通配符模式扫描（所有 ECS 规则）
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# 生成 HTML 报告
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# 多个策略
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

## 退出代码

- `0`: 未发现违规
- `1`: 发现违规
- `2`: 发现高严重性违规

有关更多详细信息，请参阅[扫描模板](../user-guide/scanning-templates)。

