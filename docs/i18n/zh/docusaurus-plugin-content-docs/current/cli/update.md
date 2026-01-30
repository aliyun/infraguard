---
title: infraguard update
---

# infraguard update

将 InfraGuard CLI 更新到最新版本或指定版本。

## 概要

```bash
infraguard update [选项]
```

## 选项

| 选项 | 类型 | 说明 |
|------|------|-------------|
| `--check` | 布尔值 | 仅检查更新而不安装 |
| `--force` | 布尔值 | 即使版本是最新也强制更新 |
| `--version` | 字符串 | 更新到指定版本 |

## 示例

### 检查更新

检查是否有新版本可用，但不安装：

```bash
infraguard update --check
```

输出：
```
正在检查更新...
当前版本：0.2.0
最新版本：0.3.0
✓ 有新版本可用：0.3.0
```

### 更新到最新版本

更新到最新可用版本：

```bash
infraguard update
```

输出：
```
正在检查更新...
当前版本：0.2.0
最新版本：0.3.0
→ 正在下载版本 0.3.0...
已下载 5.2 MiB / 5.2 MiB (100.0%)
✓ 成功更新到版本 0.3.0！
```

### 更新到指定版本

安装特定版本：

```bash
infraguard update --version 0.3.0
```

### 强制重新安装当前版本

重新安装当前版本（用于修复损坏的安装）：

```bash
infraguard update --force
```
