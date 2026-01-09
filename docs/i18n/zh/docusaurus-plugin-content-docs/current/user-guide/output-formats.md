---
title: 输出格式
---

# 输出格式

InfraGuard 支持三种输出格式：表格、JSON 和 HTML。

## 表格格式

默认格式，带有彩色编码的控制台输出。最适合交互式使用。

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## JSON 格式

用于自动化和 CI/CD 管道的机器可读格式。

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## HTML 格式

具有过滤和搜索功能的交互式报告。

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

有关详细示例，请参阅[扫描模板](./scanning-templates)。

