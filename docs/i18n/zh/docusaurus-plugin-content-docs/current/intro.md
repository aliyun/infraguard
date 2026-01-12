---
title: 欢迎使用 InfraGuard
sidebar_label: 简介
---

# InfraGuard

**策略定义基础设施安全。**

**基础设施即代码 (IaC) 合规预检 CLI**，适用于阿里云 ROS 模板。

在部署前评估您的 ROS YAML/JSON 模板是否符合安全和合规策略。

## 什么是 InfraGuard？

InfraGuard 是一个命令行工具，帮助您确保基础设施代码在部署到生产环境之前符合安全和合规标准。它使用 Open Policy Agent (OPA) 和 Rego 策略来评估您的模板。

## 核心功能

- **部署前验证** - 在问题到达生产环境之前捕获合规问题
- **策略包** - 预构建的合规包（MLPS、ISO 27001、PCI-DSS 等）
- **国际化** - 完整支持英文和中文
- **多种输出格式** - 表格、JSON 和 HTML 报告
- **可扩展** - 使用 Rego 编写自定义策略
- **快速** - 使用 Go 构建，速度快、效率高

## 支持的云服务商

- **阿里云 (Aliyun)** - 数百个规则和数十个合规包

## 快速示例

```bash
# 使用合规包扫描模板
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# 使用特定规则扫描
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# 生成 HTML 报告
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 开始使用

准备好改善您的基础设施合规性了吗？查看我们的[快速入门指南](./getting-started/quick-start)开始使用。

## 策略库

浏览我们全面的[策略参考](./policies/aliyun/rules)以查看所有可用的规则和合规包。

