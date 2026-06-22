---
title: infraguard waiver
---

# infraguard waiver

ルールの除外（waiver、抑制）を管理します。除外を使用すると、特定の違反を理由および任意の有効期限とともに、把握した上で意図的に抑制できます。概念と除外ファイルの形式については、[除外ガイド](../user-guide/waivers)を参照してください。

## サブコマンド

### list

すべての除外とそのステータス（active / expired / permanent）をリスト：
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

除外ファイルを検証します。理由の欠落、不明なルール、無効または期限切れの日付を検出します：
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # カスタムルールも認識する
```

`lint` はエラー（例：`reason` の欠落）がある場合に非ゼロで終了するため、除外ファイル自体に対する pre-commit フックや CI ゲートに適しています。

## フラグ

| フラグ | 説明 | デフォルト |
| --- | --- | --- |
| `--waivers` | 除外ファイルへのパス | `.infraguard/waivers.yaml` を自動検出 |
| `--rules-dir` | （`lint`）このディレクトリ配下のルールも既知のものとして扱う | — |

## 関連する scan フラグ

除外は `infraguard scan` の実行中に適用されます。関連するフラグは次のとおりです：

| フラグ | 説明 | デフォルト |
| --- | --- | --- |
| `--waivers` | 除外ファイルへのパス | 自動検出 |
| `--no-waivers` | すべての除外を無視（インラインコメントとファイル） | `false` |
| `--show-waived` | 除外された違反を非表示にせず表示する | `false` |
| `--fail-on-expired` | 期限切れの除外を実際の違反として扱う | `true` |

[infraguard scan](./scan) および [除外ガイド](../user-guide/waivers) を参照してください。
