---
title: ヘルパー関数
---

# ヘルパー関数

InfraGuardは、ポリシーの記述を簡素化するためのヘルパー関数を提供します。

次のようにインポートします：
```rego
import data.infraguard.helpers
```

## 利用可能な関数

| 関数 | 説明 |
|------|------|
| `resources_by_type(type)` | タイプのすべてのリソースを`{name: resource}`マップとして取得 |
| `resource_names_by_type(type)` | タイプのすべてのリソース名をリストとして取得 |
| `count_resources_by_type(type)` | タイプのリソースをカウント |
| `resource_exists(type)` | リソースタイプが存在するかチェック |
| `has_property(resource, prop)` | プロパティが存在し、nullでないかチェック |
| `get_property(resource, prop, default)` | デフォルト値でプロパティを取得 |
| `is_true(v)` / `is_false(v)` | ブール値をチェック（文字列"true"/"false"を処理） |
| `is_public_cidr(cidr)` | CIDRが`0.0.0.0/0`または`::/0`かチェック |
| `includes(list, elem)` | 要素がリスト内にあるかチェック |

## 例

```rego
# すべてのECSインスタンスを取得
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # ここにチェックロジック
}

# プロパティが存在するかチェック
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # 違反ロジック
}

# パブリックCIDRをチェック
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # 違反ロジック
}
```

より多くの例については、[ルールの記述](./writing-rules)を参照してください。
