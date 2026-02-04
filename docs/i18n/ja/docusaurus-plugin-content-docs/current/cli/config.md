---
title: infraguard config
---

# infraguard config

InfraGuardの設定を管理します。

## サブコマンド

### set

設定値を設定：
```bash
infraguard config set lang ja
```

### get

設定値を取得：
```bash
infraguard config get lang
```

### list

すべての設定値をリスト：
```bash
infraguard config list
```

### unset

設定値を削除：
```bash
infraguard config unset lang
```

## 利用可能な設定

- `lang`: 出力言語（`en`、`zh`、`es`、`fr`、`de`、`ja`、または`pt`）

詳細については、[設定](../user-guide/configuration)を参照してください。
