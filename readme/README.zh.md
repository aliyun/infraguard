<div align="center">
  <img src="../assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**策略定义基础设施安全。**

**基础设施即代码 (IaC) 合规性预检查 CLI**，适用于阿里云 ROS 模板。在部署前评估您的 ROS YAML/JSON 模板是否符合安全和合规策略。

> 💡 InfraGuard 秉承**策略即代码 (Policy as Code)** 理念 - 将合规策略作为可版本化、可测试、可复用的代码制品来管理。

**语言**: [English](../README.md) | 中文 | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [日本語](README.ja.md) | [Português](README.pt.md)

## ✨ 特性

- 🔍 **部署前验证** - 在生产环境之前发现合规性问题
- 🎯 **双重扫描模式** - 静态分析或基于云端的预览验证
- 📦 **内置规则** - 全面覆盖阿里云服务
- 🏆 **合规包** - MLPS、ISO 27001、PCI-DSS、SOC 2 等
- ✏️ **编辑器集成** - VS Code 扩展，提供 ROS 模板的自动补全、实时诊断和悬停文档
- 🌍 **多语言支持** - 支持 7 种语言（中文、英语、西班牙语、法语、德语、日语、葡萄牙语）
- 🎨 **多种输出格式** - 表格、JSON 和交互式 HTML 报告
- 🔧 **可扩展** - 使用 Rego (Open Policy Agent) 编写自定义策略
- ⚡ **快速** - 使用 Go 构建，速度快、效率高

## 🚀 快速开始

### 安装

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

或从 [GitHub Releases](https://github.com/aliyun/infraguard/releases) 下载预编译的二进制文件。

### 基本用法

```bash
# 使用合规包扫描
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# 使用特定规则扫描
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# 使用通配符模式扫描（所有规则）
infraguard scan template.yaml -p "rule:*"

# 使用通配符模式扫描（所有 ECS 规则）
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# 生成 HTML 报告
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 📚 文档

详细文档请访问我们的 [文档站点](https://aliyun.github.io/infraguard/zh/)

- **[快速开始](https://aliyun.github.io/infraguard/zh/docs/getting-started/installation)** - 安装和快速开始指南
- **[用户指南](https://aliyun.github.io/infraguard/zh/docs/user-guide/scanning-templates)** - 了解如何扫描模板和管理策略
- **[策略参考](https://aliyun.github.io/infraguard/zh/docs/policies/aliyun/rules)** - 浏览所有可用的规则和合规包
- **[开发指南](https://aliyun.github.io/infraguard/zh/docs/development/writing-rules)** - 编写自定义规则和包
- **[CLI 参考](https://aliyun.github.io/infraguard/zh/docs/cli/scan)** - 命令行界面文档
- **[常见问题](https://aliyun.github.io/infraguard/zh/docs/faq)** - 常见问题解答
