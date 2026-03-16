---
title: infraguard lsp
---

# infraguard lsp

エディタ統合用のROS Language Server Protocol（LSP）サーバーを起動します。

## 概要

```bash
infraguard lsp [flags]
```

## 説明

`lsp`コマンドは、標準入出力（stdio）で通信するLanguage Server Protocol（LSP）サーバーを起動します。VS CodeなどのエディタでROSテンプレートに対するインテリジェントな編集サポートを提供します。機能には以下が含まれます：

- **自動補完** — リソースタイプ、プロパティ、組み込み関数、Ref/GetAttターゲット
- **リアルタイム診断** — フォーマットバージョン、リソースタイプ、必須プロパティ、型の不一致
- **ホバードキュメント** — リソースとプロパティの説明、型情報、制約

LSPサーバーはYAMLとJSONの両方のテンプレート形式をサポートしています。

## フラグ

| フラグ | 型 | 説明 |
|--------|-----|------|
| `--stdio` | bool | stdioトランスポートを使用（デフォルト、エディタ互換性のため受け入れ） |

## 例

### LSPサーバーを起動

```bash
infraguard lsp
```

### 明示的なstdioフラグで起動

```bash
infraguard lsp --stdio
```

## エディタ統合

LSPサーバーは通常、エディタ拡張機能によって自動的に起動されます。VS Codeの場合は、LSPライフサイクル管理を行う[InfraGuard拡張機能](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard)をインストールしてください。

詳細については、[エディタ統合](../user-guide/editor-integration)を参照してください。

## 終了コード

- `0`: サーバーが正常に終了しました
