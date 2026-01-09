---
title: 安装
---

# 安装

## 前置要求

- **Go 1.24.6 或更高版本**（用于从源码构建）
- **Git**（用于克隆仓库）

## 从源码构建

目前，InfraGuard 以源码形式分发。按照以下步骤构建和安装：

### 1. 克隆仓库

```bash
git clone https://github.com/aliyun/infraguard.git
cd infraguard
```

### 2. 构建二进制文件

```bash
make build
```

这将在项目根目录创建 `infraguard` 二进制文件。

### 3. 安装到 PATH（可选）

您可以将二进制文件手动复制到 PATH 中的目录：

```bash
# 选项 1：系统级安装（需要 sudo）
sudo cp infraguard /usr/local/bin/

# 选项 2：用户级安装（确保 ~/bin 在您的 PATH 中）
cp infraguard ~/bin/

# 选项 3：临时将当前目录添加到 PATH
export PATH=$PATH:$(pwd)
```

或者，您也可以直接运行 InfraGuard 而无需安装（见下文）。

### 4. 验证安装

```bash
infraguard version
```

您应该看到版本信息显示。

## 替代方案：不安装直接运行

您也可以直接运行 InfraGuard 而无需安装：

```bash
go run ./cmd/infraguard <command>
```

## 下一步

现在您已经安装了 InfraGuard，请继续阅读[快速入门指南](./quick-start)以了解如何使用它。

