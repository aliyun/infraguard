---
title: エディタ統合
---

# エディタ統合

InfraGuard は、組み込みの Language Server Protocol (LSP) サーバーと VS Code 拡張機能を通じてエディタ統合を提供し、ROS テンプレートのインテリジェントな編集サポートを実現します。

## VS Code 拡張機能

### インストール

[VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=aliyun.infraguard) から **InfraGuard** 拡張機能をインストールするか、VS Code の拡張機能パネルで「InfraGuard」を検索してください。

この拡張機能には、`infraguard` CLI がインストールされ、PATH で利用可能である必要があります。詳細は [インストール](../getting-started/installation) を参照してください。

### 機能

#### 自動補完

テンプレート構造全体でコンテキストを考慮した補完を提供します：

- **リソースタイプ** — すべての ALIYUN::* リソースタイプ識別子
- **プロパティ** — 型情報付きのリソースプロパティ、必須プロパティを優先
- **組み込み関数** — `Fn::Join`、`Fn::Sub`、`Fn::Select` など
- **Ref/GetAtt ターゲット** — パラメータ、リソース、およびその属性への参照
- **パラメータ定義** — Type、Default、AllowedValues およびその他のパラメータプロパティ
- **トップレベルセクション** — ROSTemplateFormatVersion、Parameters、Resources、Outputs など

リソースタイプを入力すると、すべての必須キーを含む `Properties` ブロックが自動的に挿入されます。

#### リアルタイム診断

入力中にテンプレートを検証します：

- 欠落または無効な `ROSTemplateFormatVersion`
- 不明なリソースタイプ
- 必須プロパティの欠落
- プロパティ値の型の不一致
- 無効なパラメータ定義
- 重複する YAML キー
- 「Did you mean?」の提案付きの不明なキー

#### ホバードキュメント

要素にマウスを合わせると、コンテキストに応じたドキュメントが表示されます：

- **リソースタイプ** — 説明と公式ドキュメントへのリンク
- **プロパティ** — 型、制約、必須またはオプション、更新動作
- **組み込み関数** — 構文と使用例

#### シンタックスハイライト

ROS 固有の要素に対する強化されたシンタックスハイライト：

- `!Ref`、`Fn::Join` およびその他の組み込み関数
- `ALIYUN::*::*` リソースタイプ識別子

### サポートされるファイルタイプ

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | ROS テンプレートとして自動認識 |
| `*.ros.json` | ROS テンプレートとして自動認識 |
| `*.yaml` / `*.json` | コンテンツ内の `ROSTemplateFormatVersion` で検出 |

### コマンド

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | ROS API から最新のリソースタイプスキーマを取得 |

### ROS スキーマの更新

この拡張機能には ROS リソースタイプ用の組み込みスキーマが含まれています。最新のリソースタイプ定義で更新するには：

1. コマンドパレットを開く（`Ctrl+Shift+P` / `Cmd+Shift+P`）
2. **InfraGuard: Update ROS Schema** を実行

Alibaba Cloud の認証情報の設定が必要です。認証情報の設定については [`infraguard schema update`](../cli/schema) を参照してください。

## LSP サーバー

LSP サーバーは、Language Server Protocol をサポートする任意のエディタと統合できます。

### サーバーの起動

```bash
infraguard lsp
```

サーバーは stdio（標準入出力）で通信します。

### エディタの設定

VS Code 以外のエディタでは、LSP クライアントを次のように設定してください：

1. `infraguard lsp` でサーバーを起動
2. stdio をトランスポートとして使用
3. YAML および JSON ファイルタイプに関連付け

詳細は [`infraguard lsp`](../cli/lsp) を参照してください。
