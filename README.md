<div align="center">
  <img src="assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**Policy Defined. Infrastructure Secured.**

**Infrastructure as Code (IaC) compliance pre-check CLI** for Alibaba Cloud ROS templates. Evaluate your ROS YAML/JSON templates against security and compliance policies **before deployment**.

**Language**: English | [中文](README.zh.md)

## ✨ Features

- 🔍 **Pre-deployment Validation** - Catch compliance issues before they reach production
- 📦 **Built-in Rules** - Comprehensive coverage for Aliyun services
- 🎯 **Compliance Packs** - MLPS, ISO 27001, PCI-DSS, SOC 2, and more
- 🌍 **Internationalization** - Full support for English and Chinese
- 🎨 **Multiple Output Formats** - Table, JSON, and interactive HTML reports
- 🔧 **Extensible** - Write custom policies in Rego (Open Policy Agent)
- ⚡ **Fast** - Built in Go for speed and efficiency

## 🚀 Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/aliyun/infraguard.git
cd infraguard
make build
```

### Basic Usage

```bash
# Scan with a compliance pack
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Scan with a specific rule
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Scan with wildcard pattern (all rules)
infraguard scan template.yaml -p "rule:*"

# Scan with wildcard pattern (all ECS rules)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Generate HTML report
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

### Language Support

```bash
# Chinese output
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang zh

# English output (default)
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en
```

## 📚 Documentation

For detailed documentation, please visit our [Documentation Site](https://infraguard.example.com) *(coming soon)*

- **[Getting Started](docs/docs/getting-started/installation.md)** - Installation and quick start guide
- **[User Guide](docs/docs/user-guide/scanning-templates.md)** - Learn how to scan templates and manage policies
- **[Policy Reference](docs/docs/policies/aliyun/overview.md)** - Browse all available rules and compliance packs
- **[Development Guide](docs/docs/development/writing-rules.md)** - Write custom rules and packs
- **[CLI Reference](docs/docs/cli/scan.md)** - Command-line interface documentation
- **[FAQ](docs/docs/faq.md)** - Frequently asked questions

### Building Documentation

```bash
# Install documentation dependencies (Node.js required)
make install

# Start development server with hot reload
make doc-dev

# Generate and serve production build locally
make doc-serve

# Build static documentation site
make doc-build
```

## 📦 Policy Library

InfraGuard includes comprehensive policy coverage:

- **Hundreds of Rules** - Individual compliance checks
- **Dozens of Packs** - Pre-configured compliance collections

Browse the [full policy reference](docs/docs/policies/aliyun/overview.md) for details.

## 🔧 Development

```bash
# Build
make build

# Run tests
make test

# Generate documentation
make doc-gen

# Format code
make format
```

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## 🔗 Links

- **Documentation**: [User Guide](docs/docs/intro.md)
- **GitHub**: https://github.com/aliyun/infraguard
- **Issues**: https://github.com/aliyun/infraguard/issues
