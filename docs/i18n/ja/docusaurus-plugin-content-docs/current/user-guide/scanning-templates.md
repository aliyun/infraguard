---
title: テンプレートのスキャン
---

# テンプレートのスキャン

`infraguard scan`コマンドは、ROSテンプレートをコンプライアンスポリシーに対して評価します。

## 基本的な使用方法

```bash
infraguard scan <template> -p <policy>
```

### 必須引数

- `<template>`: ROSテンプレートファイルへのパス（YAMLまたはJSON）- 位置引数

### 必須フラグ

- `-p, --policy <id>`: 適用するポリシー（複数回使用可能）

### オプションフラグ

- `--format <format>`: 出力形式（`table`、`json`、または`html`）
- `-o, --output <file>`: 出力ファイルパス（HTMLおよびJSON形式用）
- `--lang <lang>`: 出力言語（`en`、`zh`、`es`、`fr`、`de`、`ja`、`pt`）
- `-m, --mode <mode>`: スキャンモード（ローカル分析の場合は`static`、ROS PreviewStack APIの場合は`preview`、デフォルト：`static`）
- `-i, --input <value>`: `key=value`形式、JSON形式、またはファイルパスのパラメータ値（複数回指定可能）

## ポリシータイプ

異なるタイプのポリシーでスキャンできます：

### 1. 個別のルール

特定のコンプライアンスルールでスキャン：

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. コンプライアンスパック

事前定義されたコンプライアンスパックでスキャン：

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. ワイルドカードパターンマッチング

ワイルドカードパターン（`*`）を使用して、複数のルールまたはパックに一致させます：

**すべてのルールに一致：**
```bash
infraguard scan template.yaml -p "rule:*"
```

**プレフィックスでルールに一致：**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. カスタムポリシーファイル

独自のRegoポリシーファイルでスキャン：

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. ポリシーディレクトリ

ディレクトリ内のすべてのポリシーでスキャン：

```bash
infraguard scan template.yaml -p ./my-policies/
```

## スキャンモード

InfraGuardは2つのスキャンモードをサポートしています：

### 静的モード（デフォルト）

クラウドプロバイダーへのアクセスを必要とせずに、テンプレートのローカル静的解析を実行します：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode static
```

このモードは、テンプレート構造とリソース設定をローカルで解析します。高速でクラウド認証情報を必要としませんが、すべてのROS機能をサポートしない場合があります（[ROS機能サポート](./ros-features)を参照）。

### プレビューモード

ROS PreviewStack APIを使用して、実際のクラウドプロバイダー評価でテンプレートを検証します：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview
```

プレビューモードは、ランタイム評価を必要とする機能（`Fn::GetAtt`、`Fn::GetAZs`など）に対してより正確な分析を提供します。このモードではROS認証情報の設定が必要です。

静的解析でサポートされていない機能を使用するテンプレートの場合、より正確な結果を得るために`--mode preview`の使用を推奨します。

## 複数のポリシー

1つのスキャンで複数のポリシーを適用：

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## 出力形式

### テーブル形式（デフォルト）

カラーコード付きテーブルで結果を表示：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

出力例：

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### JSON形式

CI/CD統合用の機械可読形式：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

出力：

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### HTMLレポート

フィルタリングと検索機能を備えたインタラクティブなHTMLレポート：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

ブラウザで`report.html`を開いて、インタラクティブな体験をお楽しみください。

## 終了コード

InfraGuardは、スキャン結果を示すために異なる終了コードを使用します：

- `0`: 違反が見つかりませんでした
- `1`: 違反が見つかりました
- `2`: 高嚴重度の違反が見つかりました

これはCI/CDパイプラインに役立ちます：

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "高嚴重度の違反が見つかりました！デプロイをブロックします。"
  exit 1
fi
```

## 例

### 例1：セキュリティ監査

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### 例2：コンプライアンスチェック

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang ja \
  --format json \
  -o compliance-report.json
```

### 例3：CI/CD統合

```bash
# CI/CDパイプラインで
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

### 例4：パラメータ付きプレビューモード

テンプレートパラメータを使用してプレビューモードでスキャン：

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input InstanceType=ecs.c6.large \
  --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd
```

JSONファイルからパラメータを提供することもできます：

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input parameters.json
```

## ヒント

1. **クイックスタートパックから始める**：基本的なチェックには`pack:aliyun:quick-start-compliance-pack`を使用します
2. **複数のパックを使用**：包括的なカバレッジのために複数のパックを組み合わせます
3. **レポートを保存**：ステークホルダーレポートにはHTML形式、自動化にはJSON形式を使用します
4. **言語を一度設定**：`infraguard config set lang ja`を使用して、`--lang`フラグの繰り返しを避けます

## 次のステップ

- [ポリシーの管理](./managing-policies)について学ぶ
- [出力形式](./output-formats)を詳しく探索する
- [設定](./configuration)を構成する
