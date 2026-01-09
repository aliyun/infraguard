<div align="center">
  <img src="assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**策略定义基础设施安全。**

**基础设施即代码 (IaC) 合规性预检查 CLI**，适用于阿里云 ROS 模板。在部署前评估您的 ROS YAML/JSON 模板是否符合安全和合规策略。

**语言**: [English](README.md) | 中文

## ✨ 特性

- 🔍 **部署前验证** - 在生产环境之前发现合规性问题
- 📦 **内置规则** - 全面覆盖阿里云服务
- 🎯 **合规包** - MLPS、ISO 27001、PCI-DSS、SOC 2 等
- 🌍 **国际化** - 完整支持英文和中文
- 🎨 **多种输出格式** - 表格、JSON 和交互式 HTML 报告
- 🔧 **可扩展** - 使用 Rego (Open Policy Agent) 编写自定义策略
- ⚡ **快速** - 使用 Go 构建，速度快、效率高

## 🚀 快速开始

### 安装

```bash
# 克隆并构建
git clone https://github.com/aliyun/infraguard.git
cd infraguard
make build
```

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

### 语言支持

```bash
# 中文输出
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang zh

# 英文输出（默认）
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en
```

## 📚 文档

详细文档请访问我们的 [文档站点](https://infraguard.example.com) *(即将推出)*

- **[快速开始](docs/docs/getting-started/installation.md)** - 安装和快速开始指南
- **[用户指南](docs/docs/user-guide/scanning-templates.md)** - 了解如何扫描模板和管理策略
- **[策略参考](docs/docs/policies/aliyun/overview.md)** - 浏览所有可用的规则和合规包
- **[开发指南](docs/docs/development/writing-rules.md)** - 编写自定义规则和包
- **[CLI 参考](docs/docs/cli/scan.md)** - 命令行界面文档
- **[常见问题](docs/docs/faq.md)** - 常见问题解答

### 构建文档

```bash
# 安装文档依赖（需要 Node.js）
make install

# 启动开发服务器（热重载）
make doc-dev

# 本地生成并服务生产构建
make doc-serve

# 构建静态文档站点
make doc-build
```

## 📦 策略库

InfraGuard 包含全面的策略覆盖：

- **数百条规则** - 单独的合规性检查
- **数十个包** - 预配置的合规性集合

浏览 [完整策略参考](docs/docs/policies/aliyun/overview.md) 了解详情。

## 🔧 开发

```bash
# 构建
make build

# 运行测试
make test

# 生成文档
make doc-gen

# 格式化代码
make format
```

## 📄 许可证

Apache License 2.0 - 详见 [LICENSE](LICENSE)

## 🔗 链接

- **文档**: [用户指南](docs/docs/intro.md)
- **GitHub**: https://github.com/aliyun/infraguard
- **Issues**: https://github.com/aliyun/infraguard/issues

