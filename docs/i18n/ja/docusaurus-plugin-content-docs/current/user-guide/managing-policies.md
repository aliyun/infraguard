---
title: ポリシーの管理
---

# ポリシーの管理

InfraGuardでポリシーを発見、管理、更新する方法を学びます。

## ポリシーのリスト

### すべてのポリシーをリスト

利用可能なすべてのルールとパックを表示：

```bash
infraguard policy list
```

これにより以下が表示されます：
- すべての組み込みルール
- すべてのコンプライアンスパック
- カスタムポリシー（ある場合）

### プロバイダーでフィルタ

現在、InfraGuardはAliyunポリシーをサポートしています。今後のバージョンでは追加のプロバイダーをサポートします。

## ポリシーの詳細

### ルール情報の取得

特定のルールに関する詳細情報を表示：

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

出力には以下が含まれます：
- ルールIDと名前
- 重要度レベル
- 説明
- 失敗の理由
- 推奨事項
- 影響を受けるリソースタイプ

### パック情報の取得

コンプライアンスパックの詳細を表示：

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

出力には以下が含まれます：
- パックIDと名前
- 説明
- 含まれるルールのリスト

## ポリシーの更新

InfraGuardには組み込みポリシーが含まれていますが、最新のポリシーライブラリをダウンロードすることもできます：

```bash
infraguard policy update
```

これにより、ポリシーが`~/.infraguard/policies/`にダウンロードされ、組み込みポリシーよりも優先されます。

## ポリシーのクリーン

ユーザーディレクトリからダウンロードしたポリシーを削除するには：

```bash
infraguard policy clean
```

このコマンドは：
- `~/.infraguard/policies/`からすべてのポリシーを削除します
- デフォルトで確認を求めます
- 組み込みポリシーには影響しません（利用可能なままです）
- `.infraguard/policies/`のワークスペースポリシーには影響しません

### 強制クリーン（確認なし）

スクリプトまたは非対話環境の場合：

```bash
infraguard policy clean --force
# または
infraguard policy clean -f
```

### ポリシー読み込み優先順位

InfraGuardは、次の優先順位（高から低）で3つのソースからポリシーを読み込みます：

1. **ワークスペースローカルポリシー**：`.infraguard/policies/`（現在の作業ディレクトリからの相対パス）
2. **ユーザーローカルポリシー**：`~/.infraguard/policies/`
3. **組み込みポリシー**：バイナリに組み込まれています（フォールバック）

より高い優先順位のソースからの同じIDのポリシーは、より低い優先順位のものを上書きします。これにより以下が可能になります：
- **プロジェクト固有のポリシー**：プロジェクトとバージョン管理される`.infraguard/policies/`でカスタムルールを定義
- **ユーザーカスタマイズ**：`~/.infraguard/policies/`を介して組み込みポリシーをグローバルに上書き
- **シームレスなフォールバック**：組み込みポリシーは設定なしで動作します

## カスタムポリシーの検証

カスタムポリシーを使用する前に、それらを検証します：

```bash
infraguard policy validate ./my-custom-rule.rego
```

これにより以下がチェックされます：
- Rego構文
- 必要なメタデータ（`rule_meta`または`pack_meta`）
- 適切なdenyルール構造

### 検証オプション

```bash
# 単一ファイルを検証
infraguard policy validate rule.rego

# ディレクトリを検証
infraguard policy validate ./policies/

# 出力言語を指定
infraguard policy validate rule.rego --lang ja
```

## ポリシーのフォーマット

OPAフォーマッタを使用してポリシーファイルをフォーマット：

```bash
# フォーマットされた出力を表示
infraguard policy format rule.rego

# 変更をファイルに書き戻す
infraguard policy format rule.rego --write

# 変更のdiffを表示
infraguard policy format rule.rego --diff
```

## ポリシーの整理

### 組み込みポリシー

バイナリ内の以下に配置：
- `policies/aliyun/rules/` - 個別のルール
- `policies/aliyun/packs/` - コンプライアンスパック
- `policies/aliyun/lib/` - ヘルパーライブラリ

### カスタムポリシー

#### ワークスペースローカルポリシー（プロジェクト固有）

プロジェクトディレクトリにプロジェクト固有のポリシーを保存：
- `.infraguard/policies/<provider>/rules/` - プロジェクト固有のルール
- `.infraguard/policies/<provider>/packs/` - プロジェクト固有のパック
- `.infraguard/policies/<provider>/lib/` - プロジェクト固有のヘルパーライブラリ

これらのポリシーは、プロジェクトディレクトリ内からInfraGuardコマンドを実行すると自動的に読み込まれ、IaCテンプレートと一緒にバージョン管理できます。

#### ユーザーローカルポリシー（グローバル）

ホームディレクトリにグローバルカスタムポリシーを保存：
- `~/.infraguard/policies/<provider>/rules/` - グローバルカスタムルール
- `~/.infraguard/policies/<provider>/packs/` - グローバルカスタムパック
- `~/.infraguard/policies/<provider>/lib/` - グローバルカスタムヘルパーライブラリ

これらのポリシーはすべてのプロジェクトで利用可能で、組み込みポリシーを上書きできます。
