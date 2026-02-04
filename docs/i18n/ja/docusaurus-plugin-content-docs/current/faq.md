---
title: よくある質問
---

# よくある質問

## 一般

### InfraGuardとは？

InfraGuardは、デプロイ前にInfrastructure as Code (IaC) テンプレートをコンプライアンスポリシーに対して検証するコマンドラインツールです。開発サイクルの早い段階でセキュリティとコンプライアンスの問題を検出するのに役立ちます。

### どのクラウドプロバイダーがサポートされていますか？

現在、InfraGuardはAlibaba Cloud (Aliyun) ROSテンプレートをサポートしています。他のプロバイダーのサポートは今後のバージョンで追加される可能性があります。

### InfraGuardは無料ですか？

はい、InfraGuardはオープンソースで、Apache License 2.0の下でリリースされています。

## 使用

### テンプレートをスキャンするにはどうすればよいですか？

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

より多くの例については[クイックスタートガイド](./getting-started/quick-start)を参照してください。

### 1つのスキャンで複数のポリシーを使用できますか？

はい！複数の`-p`フラグを使用します：

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### 利用可能な出力形式は何ですか？

InfraGuardは3つの形式をサポートしています：
- **テーブル**：カラーコンソール出力（デフォルト）
- **JSON**：CI/CD用の機械可読形式
- **HTML**：インタラクティブレポート

### 言語を変更するにはどうすればよいですか？

`--lang`フラグを使用するか、永続的に設定します：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang ja
# または永続的に設定
infraguard config set lang ja
```

InfraGuardは7言語をサポートしています：
- `en` - English（英語）
- `zh` - Chinese（中文）
- `es` - Spanish（スペイン語）
- `fr` - French（フランス語）
- `de` - German（ドイツ語）
- `ja` - Japanese（日本語）
- `pt` - Portuguese（ポルトガル語）

## ポリシー

### ポリシーはどこに保存されますか？

ポリシーはバイナリに埋め込まれています。カスタムポリシーは`~/.infraguard/policies/`にも保存できます。

### ポリシーを更新するにはどうすればよいですか？

```bash
infraguard policy update
```

### カスタムポリシーを書くことはできますか？

はい！ポリシーはRego（Open Policy Agent言語）で記述されます。[開発ガイド](./development/writing-rules)を参照してください。

### カスタムポリシーを検証するにはどうすればよいですか？

```bash
infraguard policy validate my-rule.rego
```
