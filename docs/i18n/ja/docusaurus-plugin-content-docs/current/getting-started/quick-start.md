---
title: クイックスタート
---

# クイックスタート

このガイドは、わずか数分でInfraGuardを始めるのに役立ちます。

## ステップ1：サンプルROSテンプレートを作成

次の内容で`template.yaml`というファイルを作成します：

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: Sample ECS instance

Resources:
  MyECS:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      ImageId: 'centos_7'
      InstanceType: 'ecs.t5-lc1m1.small'
      AllocatePublicIP: true
      SecurityGroupId: 'sg-xxxxx'
      VpcId: 'vpc-xxxxx'
      VSwitchId: 'vsw-xxxxx'
```

## ステップ2：最初のスキャンを実行

組み込みルールを使用してテンプレートをスキャンします：

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

ECSインスタンスにパブリックIPが割り当てられていることを示す出力が表示されるはずです。これはセキュリティ上の懸念事項です。

## ステップ3：コンプライアンスパックを使用

個別のルールの代わりに、コンプライアンスパック全体でスキャンできます：

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## ステップ4：レポートを生成

InfraGuardは複数の出力形式をサポートしています：

### テーブル形式（デフォルト）

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### JSON形式

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### HTMLレポート

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

ブラウザで`report.html`を開いて、インタラクティブなレポートを表示します。

## ステップ5：利用可能なポリシーをリスト

利用可能なすべてのルールとパックを表示するには：

```bash
# すべてのポリシーをリスト
infraguard policy list

# 特定のルールの詳細を取得
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# コンプライアンスパックの詳細を取得
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## 一般的な使用例

### 複数のポリシーでスキャン

1つのスキャンで複数のポリシーを適用できます：

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### 言語設定

InfraGuardは7言語をサポートしています：

```bash
# 日本語出力
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang ja

# 英語出力
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# その他のサポート言語：zh（中国語）、es（スペイン語）、fr（フランス語）、de（ドイツ語）、pt（ポルトガル語）
```

言語を永続的に設定することもできます：

```bash
infraguard config set lang ja
```

サポートされている言語コード：`en`、`zh`、`es`、`fr`、`de`、`ja`、`pt`。デフォルトはシステムロケールに基づいて自動検出されます。

## 次のステップ

- **詳細を学ぶ**：詳細情報については[ユーザーガイド](../user-guide/scanning-templates)をお読みください
- **ポリシーを探索**：[ポリシーリファレンス](../policies/aliyun/rules)を参照して、利用可能なすべてのルールとパックを確認してください
- **カスタムポリシーを書く**：[開発ガイド](../development/writing-rules)を確認して、独自のルールを作成してください

## ヘルプの取得

問題が発生した場合：

1. [FAQ](../faq)ページを確認してください
2. エラーメッセージを注意深く確認してください - 通常は役立つヒントが含まれています
3. [GitHub](https://github.com/aliyun/infraguard/issues)で問題を報告してください
