---
title: 扫描模板
---

# 扫描模板

`infraguard scan` 命令根据合规策略评估您的 ROS 模板。

## 基本用法

```bash
infraguard scan <template> -p <policy>
```

### 必需参数

- `<template>`: ROS 模板文件路径（YAML 或 JSON）- 位置参数

### 必需选项

- `-p, --policy <id>`: 要应用的策略（可多次使用）

### 可选选项

- `--format <format>`: 输出格式（`table`、`json` 或 `html`）
- `-o, --output <file>`: 输出文件路径（用于 HTML 和 JSON 格式）
- `--lang <lang>`: 输出语言（`en` 或 `zh`）

## 策略类型

您可以使用不同类型的策略进行扫描：

### 1. 单个规则

使用特定的合规规则扫描：

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. 合规包

使用预定义的合规包扫描：

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. 通配符模式匹配

使用通配符模式（`*`）匹配多个规则或包：

**匹配所有规则：**
```bash
infraguard scan template.yaml -p "rule:*"
```

**按前缀匹配规则：**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. 自定义策略文件

使用您自己的 Rego 策略文件扫描：

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. 策略目录

使用目录中的所有策略扫描：

```bash
infraguard scan template.yaml -p ./my-policies/
```

## 多个策略

在一次扫描中应用多个策略：

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## 输出格式

### 表格格式（默认）

以彩色编码的表格显示结果：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

示例输出：

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### JSON 格式

用于 CI/CD 集成的机器可读格式：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

输出：

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### HTML 报告

具有过滤和搜索功能的交互式 HTML 报告：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

在浏览器中打开 `report.html` 以获得交互式体验。

## 退出代码

InfraGuard 使用不同的退出代码来指示扫描结果：

- `0`: 未发现违规
- `1`: 发现违规
- `2`: 发现高严重性违规

这对 CI/CD 管道很有用：

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "发现高严重性违规！阻止部署。"
  exit 1
fi
```

## 示例

### 示例 1：安全审计

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### 示例 2：合规检查

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang zh \
  --format json \
  -o compliance-report.json
```

### 示例 3：CI/CD 集成

```bash
# 在您的 CI/CD 管道中
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

## 提示

1. **从快速入门包开始**：使用 `pack:aliyun:quick-start-compliance-pack` 进行基本检查
2. **使用多个包**：组合多个包以获得全面覆盖
3. **保存报告**：使用 HTML 格式用于利益相关者报告，JSON 用于自动化
4. **一次性设置语言**：使用 `infraguard config set lang zh` 避免重复使用 `--lang` 选项

## 下一步

- 了解[管理策略](./managing-policies)
- 详细了解[输出格式](./output-formats)
- 配置[设置](./configuration)

