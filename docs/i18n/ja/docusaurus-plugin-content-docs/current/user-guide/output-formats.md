---
title: 出力形式
---

# 出力形式

InfraGuardは3つの出力形式をサポートしています：テーブル、JSON、HTML。

## テーブル形式

カラーコード付きコンソール出力のデフォルト形式。対話的な使用に最適です。

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## JSON形式

自動化とCI/CDパイプライン用の機械可読形式。

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## HTML形式

フィルタリングと検索機能を備えたインタラクティブなレポート。

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

詳細な例については、[テンプレートのスキャン](./scanning-templates)を参照してください。
