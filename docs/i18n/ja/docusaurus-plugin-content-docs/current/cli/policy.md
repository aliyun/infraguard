---
title: infraguard policy
---

# infraguard policy

コンプライアンスポリシーを管理します。

## サブコマンド

### list

利用可能なすべてのポリシーをリスト：
```bash
infraguard policy list
```

### get

特定のポリシーの詳細を取得：
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

ポリシーライブラリを更新：
```bash
infraguard policy update
```

### new

新しいカスタムルールをスキャフォールディング（Rego のスケルトン + テストフィクスチャ）：
```bash
# ROS と Terraform の両方向けにルールを生成
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# コンプライアンスパックのスケルトンを生成
infraguard policy new --pack my-team-baseline
```

生成されたファイルは `--dir`（デフォルト `./policies`）配下に置かれ、`infraguard scan -p ./policies <template>` および `infraguard policy test` でそのまま使用できます。[カスタムルールの作成](../development/scaffolding-rules)を参照してください。

| フラグ | 説明 | デフォルト |
| --- | --- | --- |
| `--iac` | 対象 IaC：`ros`、`terraform`、または `both` | `both` |
| `--severity` | `high`、`medium`、または `low` | `medium` |
| `--resource-type` | ROS リソースタイプ（繰り返し可能） | — |
| `--tf-resource-type` | Terraform リソースタイプ（繰り返し可能） | — |
| `--dir` | 出力ルートディレクトリ | `./policies` |
| `--name-en` / `--name-zh` | ルール名 | ルール ID |
| `--desc-en` / `--desc-zh` | ルールの説明 | `TODO` |
| `--no-test` | テストフィクスチャを生成しない | `false` |
| `--force` | 既存ファイルを上書きする | `false` |
| `--pack` | 指定した ID でパックのスケルトンを生成 | — |

### test

フィクスチャを使用してルールの動作テストを実行：
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

各ルールについて、`<dir>/testdata/aliyun/rules/<rule>/` 配下のフィクスチャが評価されます：`compliant` フィクスチャはそのルールの違反を**まったく**生成してはならず、`violation` フィクスチャは**少なくとも 1 つ**生成しなければなりません。終了コードは、すべてのケースが合格した場合は `0`、失敗の場合は `1`、フィクスチャが見つからない場合は `2`（`--allow-empty` を指定した場合を除く）です。[ルールのテスト](../development/scaffolding-rules)を参照してください。

| フラグ | 説明 | デフォルト |
| --- | --- | --- |
| `--dir` | `rules/` と `testdata/` を含むルートディレクトリ | `./policies` |
| `--rule` | 指定したルール ID のみをテスト（繰り返し可能） | すべて |
| `--iac` | テストする IaC：`ros`、`terraform`、または `both` | `both` |
| `--format` | 出力形式：`table` または `json` | `table` |
| `--allow-empty` | フィクスチャが見つからない場合でも `0` で終了する | `false` |

### validate

カスタムポリシーを検証：
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang ja
```

### format

ポリシーファイルをフォーマット：
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

ユーザーポリシーディレクトリをクリーン：
```bash
infraguard policy clean              # 確認付きの対話モード
infraguard policy clean --force      # 確認をスキップ
infraguard policy clean -f           # 短いフラグ
```

`~/.infraguard/policies/`からすべてのポリシーを削除します。埋め込みポリシーやワークスペースポリシーには影響しません。

詳細については、[ポリシーの管理](../user-guide/managing-policies)を参照してください。
