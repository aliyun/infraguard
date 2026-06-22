---
title: ルールのスキャフォールディングとテスト
---

# カスタムルールのスキャフォールディングとテスト

InfraGuard には 600 以上の組み込みルールが付属していますが、ほとんどのチームには独自のコンプライアンス要件（命名規則、必須のコストタグ、内部 CIDR ルールなど）もあります。このページでは、CLI から離れることなく独自のルールを作成・検証する近道を示します。

ループは次のとおりです：**`policy new` → 編集 → `policy test` → `scan`**。

## 1. ルールをスキャフォールディングする

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

これにより、`./policies` 配下に編集可能なスケルトンが生成されます（`--dir` で上書き可能）：

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

生成された `.rego` には、`rule_meta` ブロック（id、severity、7 言語の名前プレースホルダー、リソースタイプ）と、`TODO` マーカー付きの最小限の `deny` ルールが事前に記入されています。カスタムルールは組み込みヘルパー（`data.infraguard.helpers`、`data.infraguard.helpers.terraform`）を自由にインポートできます — スキャンまたはテスト時に InfraGuard が自動的に注入します。[ヘルパー関数](./helper-functions) および [ルールの記述](./writing-rules) を参照してください。

## 2. ロジックを実装する

生成されたファイルを編集し、`TODO` マーカーを置き換えます。例えば ROS ルールの場合：

```rego
is_compliant(resource) if {
	helpers.has_tags(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Tags"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
```

次に、フィクスチャを意味のあるものにします：`compliant` フィクスチャはルールを満たす必要があり（例：`owner` タグを含める）、`violation` フィクスチャはルールに違反する必要があります。

## ルールのテスト

`infraguard policy test` は、`scan` と同じエンジンを使用して各ルールをそのフィクスチャに対して評価します：

- `compliant` フィクスチャはそのルールの違反を**まったく**生成してはなりません。
- `violation` フィクスチャは**少なくとも 1 つ**生成しなければなりません。

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # 機械可読、CI 用
```

出力例：

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

終了コード：`0` すべて合格、`1` ケースが失敗、`2` フィクスチャが見つからない（`--allow-empty` で上書き）。これにより、`policy test` はカスタムルールリポジトリにとって自然な CI ゲートになります。

## 3. スキャンでルールを使用する

`scan` をポリシーディレクトリに向けます：

```bash
infraguard scan -p ./policies my-template.yaml
```

## ヒント

- `policy test` が動作テストを実行する前に、`infraguard policy validate ./policies` を使用して静的チェック（構文、`rule_meta` の完全性）を行ってください。
- 同じルールの ROS 実装と Terraform 実装は同じ ID 配下に保ってください。それらはルールのメタデータを共有し、自動的にマージされます。
- フラグの完全な一覧については、[policy CLI リファレンス](../cli/policy) を参照してください。
