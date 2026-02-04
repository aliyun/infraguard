---
title: infraguard update
---

# infraguard update

InfraGuard CLIを最新バージョンまたは特定のバージョンに更新します。

## 概要

```bash
infraguard update [flags]
```

## フラグ

| フラグ | 型 | 説明 |
|--------|-----|------|
| `--check` | boolean | インストールせずに更新をチェック |
| `-f`, `--force` | boolean | バージョンが最新でも強制的に更新 |
| `--version` | string | 特定のバージョンに更新 |

## 例

### 更新をチェック

インストールせずに新しいバージョンが利用可能かどうかを確認：

```bash
infraguard update --check
```

出力：
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
✓ A new version is available: 0.5.0
```

### 最新バージョンに更新

利用可能な最新バージョンに更新：

```bash
infraguard update
```

出力：
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
→ Downloading version 0.5.0...
Downloaded 39.5 MiB / 39.5 MiB (100.0%)
✓ Successfully updated to version 0.5.0!
```

### 特定のバージョンに更新

特定のバージョンをインストール：

```bash
infraguard update --version 0.5.0
```

### 現在のバージョンを強制的に再インストール

現在のバージョンを再インストール：

```bash
infraguard update --force
# または
infraguard update -f
```
