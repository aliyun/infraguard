---
title: ポリシーディレクトリ構造
---

# ポリシーディレクトリ構造

InfraGuardは、ポリシーを読み込むための明確な優先順位システムを持つ複数のポリシーソースをサポートしています。

## ディレクトリ構造

### 標準ポリシーディレクトリ構造

ポリシーはプロバイダー優先のディレクトリ構造に従います：

```
{policy-root}/
├── {provider}/
│   ├── rules/
│   │   ├── rule1.rego            # 個別のルール
│   │   └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # コンプライアンスパック
│       └── pack2.rego
```

**例：**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── metadata-ros-composer-check.rego
│   │   ├── metadata-templatetags-check.rego
│   │   ├── parameter-sensitive-noecho-check.rego
│   │   └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

## ポリシー読み込み優先順位

InfraGuardは、次の優先順位（高から低）で複数のソースからポリシーを読み込みます：

1. **ワークスペースローカルポリシー**：`.infraguard/policies/`（現在の作業ディレクトリ）
2. **ユーザーローカルポリシー**：`~/.infraguard/policies/`（ユーザーのホームディレクトリ）
3. **組み込みポリシー**：バイナリに組み込まれています

より高い優先順位のソースからの同じIDのポリシーは、より低い優先順位のソースのポリシーを上書きします。

## ワークスペースローカルポリシー

ワークスペースローカルポリシーは、現在の作業ディレクトリ内の`.infraguard/policies/`ディレクトリに保存されます。これは最高優先順位の場所で、以下に最適です：

- プロジェクト固有のカスタムルールとパック
- 特定のプロジェクトの組み込みポリシーの上書き
- ユーザーローカルまたは組み込みに昇格する前に新しいポリシーをテスト

### ワークスペースポリシーの使用

1. ディレクトリ構造を作成：

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. カスタムルールまたはパックを適切なディレクトリに追加

3. 利用可能なポリシーをリスト：

```bash
infraguard policy list
```

ワークスペースポリシーは、ID形式`rule:myprovider:rule-name`または`pack:myprovider:pack-name`で表示されます

4. スキャンで使用：

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## ユーザーローカルポリシー

ユーザーローカルポリシーは、ホームディレクトリの`~/.infraguard/policies/`に保存されます。これらのポリシーは、ユーザーアカウントのすべてのプロジェクトで利用可能です。

## ID生成

InfraGuardは、ディレクトリ構造に基づいてポリシーIDを自動生成します：

- **ルール**：`rule:{provider}:{rule-id}`
- **パック**：`pack:{provider}:{pack-id}`

`{provider}`は親ディレクトリ名（例：`solution`、`aliyun`、`custom`）から派生します。

## 次のステップ

- [ルールの記述](./writing-rules)を学ぶ
- [パックの記述](./writing-packs)を学ぶ
- [ポリシーの検証](./policy-validation)を参照
