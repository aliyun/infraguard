---
title: 安装
---

# 安装

## 使用 go install 安装（推荐）

安装 InfraGuard 最简单的方式是使用 `go install`：

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

这将下载、编译并安装 `infraguard` 二进制文件到您的 `$GOPATH/bin` 目录（如果未设置 `GOPATH`，则为 `$HOME/go/bin`）。

确保您的 Go bin 目录在 PATH 中：

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### 验证安装

```bash
infraguard version
```

您应该看到版本信息显示。

## 下载预编译的二进制文件

您可以从 [GitHub Releases](https://github.com/aliyun/infraguard/releases) 下载预编译的二进制文件。

### 支持的平台

| 平台 | 架构 | 文件名 |
|------|------|--------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### 安装步骤

1. 从 [Releases 页面](https://github.com/aliyun/infraguard/releases) 下载适合您平台的二进制文件

2. 添加可执行权限（Linux/macOS）：

```bash
chmod +x infraguard-*
```

3. 移动到 PATH 目录：

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# 或仅用户安装
mv infraguard-* ~/bin/infraguard
```

4. 验证安装：

```bash
infraguard version
```

## 从源码构建（可选）

如果您需要修改代码或希望从源码构建：

### 前置要求

- **Go 1.24.6 或更高版本**
- **Git**
- **Make**

### 步骤

```bash
# 克隆仓库
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# 构建二进制文件
make build

# 可选：安装到 PATH
sudo cp infraguard /usr/local/bin/
```

## 下一步

现在您已经安装了 InfraGuard，请继续阅读[快速入门指南](./quick-start)以了解如何使用它。

