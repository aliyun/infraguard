<div align="center">
  <img src="../assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**ポリシー定義。インフラストラクチャ保護。**

**Infrastructure as Code (IaC) コンプライアンス事前チェック CLI**（Alibaba Cloud ROSテンプレート用）。デプロイ前にROS YAML/JSONテンプレートをセキュリティおよびコンプライアンスポリシーに対して評価します。

> 💡 InfraGuardは**Policy as Code**の理念を採用しています - コンプライアンスポリシーをバージョン管理可能で、テスト可能で、再利用可能なコードアーティファクトとして扱います。

**言語**: [English](../README.md) | [中文](README.zh.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | 日本語 | [Português](README.pt.md)

## ✨ 機能

- 🔍 **デプロイ前検証** - 本番環境に到達する前にコンプライアンスの問題を検出
- 🎯 **デュアルスキャンモード** - 静的解析またはクラウドベースのプレビュー検証
- 📦 **組み込みルール** - Aliyunサービスの包括的なカバレッジ
- 🏆 **コンプライアンスパック** - MLPS、ISO 27001、PCI-DSS、SOC 2など
- 🌍 **多言語サポート** - 7言語で利用可能（日本語、英語、中国語、スペイン語、フランス語、ドイツ語、ポルトガル語）
- 🎨 **複数の出力形式** - テーブル、JSON、インタラクティブなHTMLレポート
- 🔧 **拡張可能** - Rego（Open Policy Agent）でカスタムポリシーを記述
- ⚡ **高速** - Goで構築され、速度と効率を実現

## 🚀 クイックスタート

### インストール

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

または、[GitHub Releases](https://github.com/aliyun/infraguard/releases)からプリコンパイル済みバイナリをダウンロードしてください。

### 基本的な使用方法

```bash
# コンプライアンスパックでスキャン
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# 特定のルールでスキャン
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# ワイルドカードパターンでスキャン（すべてのルール）
infraguard scan template.yaml -p "rule:*"

# ワイルドカードパターンでスキャン（すべてのECSルール）
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# HTMLレポートを生成
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 📚 ドキュメント

詳細なドキュメントについては、[ドキュメントサイト](https://aliyun.github.io/infraguard)をご覧ください

- **[はじめに](https://aliyun.github.io/infraguard/docs/getting-started/installation)** - インストールとクイックスタートガイド
- **[ユーザーガイド](https://aliyun.github.io/infraguard/docs/user-guide/scanning-templates)** - テンプレートのスキャンとポリシーの管理方法を学ぶ
- **[ポリシーリファレンス](https://aliyun.github.io/infraguard/docs/policies/aliyun/rules)** - 利用可能なすべてのルールとコンプライアンスパックを閲覧
- **[開発ガイド](https://aliyun.github.io/infraguard/docs/development/writing-rules)** - カスタムルールとパックを記述
- **[CLIリファレンス](https://aliyun.github.io/infraguard/docs/cli/scan)** - コマンドラインインターフェースのドキュメント
- **[FAQ](https://aliyun.github.io/infraguard/docs/faq)** - よくある質問
