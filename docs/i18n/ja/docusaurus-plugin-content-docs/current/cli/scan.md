---
title: infraguard scan
---

# infraguard scan

ROSテンプレートをスキャンしてコンプライアンス違反を検出します。

## 概要

```bash
infraguard scan <template> -p <policy> [flags]
```

## 引数

- `<template>`: ROSテンプレートファイルへのパス（必須、位置引数）

## フラグ

| フラグ | 型 | 説明 |
|--------|-----|------|
| `-p, --policy <id>` | string | 適用するポリシー（複数回使用可能、必須） |
| `--format <format>` | string | 出力形式（`table`、`json`、`html`） |
| `-o, --output <file>` | string | 出力ファイルパス |
| `--lang <lang>` | string | 出力言語（`en`、`zh`、`es`、`fr`、`de`、`ja`、`pt`） |
| `-m, --mode <mode>` | string | スキャンモード：ローカル分析の場合は`static`、ROS PreviewStack APIの場合は`preview`（デフォルト：`static`） |
| `-i, --input <value>` | string | `key=value`形式、JSON形式、またはファイルパスのパラメータ値（複数回指定可能） |

## 例

```bash
# ルールでスキャン
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# パックでスキャン
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# ワイルドカードパターンでスキャン（すべてのルール）
infraguard scan template.yaml -p "rule:*"

# ワイルドカードパターンでスキャン（すべてのECSルール）
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# HTMLレポートを生成
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# プレビューモードを使用してスキャン
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview

# テンプレートパラメータでスキャン
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --input InstanceType=ecs.c6.large --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd

# JSONファイルからのパラメータでプレビューモード
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview --input parameters.json
```

## 終了コード

- `0`: 違反が見つかりませんでした
- `1`: 違反が見つかりました
- `2`: 高嚴重度の違反が見つかりました

詳細については、[テンプレートのスキャン](../user-guide/scanning-templates)を参照してください。
