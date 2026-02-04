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

## 策略即代码

InfraGuard 秉承**策略即代码 (Policy as Code)** 理念 - 将合规策略视为可以版本化、测试和自动化的一等公民代码制品。

- **版本控制** - 将策略与基础设施代码一起存储在 Git 中。跟踪变更、审查历史记录，并在需要时回滚。
- **自动化测试** - 使用示例模板为策略编写单元测试。确保策略在应用到生产环境之前正确工作。
- **代码审查** - 对策略变更应用与应用代码相同的同行评审流程。通过协作尽早发现问题。
- **CI/CD 集成** - 将策略检查集成到 CI/CD 流水线中。自动验证每次基础设施变更是否符合合规要求。
- **可复用性** - 将单个规则组合成合规包。跨团队和项目共享策略以保持一致性。
- **声明式** - 使用 Rego 的声明式语法定义合规的*标准*，而非*检查方式*。关注结果，而非实现。

## 核心功能

- **部署前验证** - 在问题到达生产环境之前捕获合规问题
- **策略包** - 预构建的合规包（MLPS、ISO 27001、PCI-DSS 等）
- **国际化** - 完整支持 7 种语言（英语、中文、西班牙语、法语、德语、日语、葡萄牙语）
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

