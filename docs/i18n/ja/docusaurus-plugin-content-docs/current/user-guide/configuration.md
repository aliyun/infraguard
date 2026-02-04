---
title: 設定
---

# 設定

InfraGuardは設定を`~/.infraguard/config.yaml`に保存します。

## 設定の管理

### 値を設定

```bash
infraguard config set lang ja
```

### 値を取得

```bash
infraguard config get lang
```

### すべての設定をリスト

```bash
infraguard config list
```

### 値を削除

```bash
infraguard config unset lang
```

## 利用可能な設定

### 言語 (`lang`)

デフォルトの出力言語を設定します：

```bash
infraguard config set lang zh  # Chinese (中文)
infraguard config set lang en  # English (英語)
infraguard config set lang es  # Spanish (スペイン語)
infraguard config set lang fr  # French (フランス語)
infraguard config set lang de  # German (ドイツ語)
infraguard config set lang ja  # Japanese (日本語)
infraguard config set lang pt  # Portuguese (ポルトガル語)
```

InfraGuardは7言語をサポートしています：`en`、`zh`、`es`、`fr`、`de`、`ja`、`pt`。デフォルトはシステムロケールに基づいて自動検出されます。

## 設定ファイル

設定ファイルは`~/.infraguard/config.yaml`にあります：

```yaml
lang: ja
```

必要に応じて、このファイルを直接編集できます。
