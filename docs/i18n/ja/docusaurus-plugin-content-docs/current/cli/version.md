---
title: infraguard version
---

# infraguard version

InfraGuard CLIとOPAのバージョン情報を表示します。

## 概要

```bash
infraguard version [flags]
```

## 説明

`version`コマンドは、以下のバージョン情報を表示します：
- InfraGuard CLIのバージョン
- InfraGuardが使用するOPA（Open Policy Agent）のバージョン

## 例

### バージョン情報を表示

```bash
infraguard version
```

出力：
```
InfraGuard: 0.5.0
OPA: 1.12.1
```

## 終了コード

- `0`: 成功
