---
title: ルールの記述
---

# カスタムルールの記述

InfraGuard用のカスタムコンプライアンスルールを記述する方法を学びます。

## ルール構造

ルールは次の構造でRego（Open Policy Agent言語）で記述されます：

```rego
package infraguard.rules.aliyun.my_custom_rule

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "my-custom-rule",
    "name": {
        "en": "My Custom Rule",
        "zh": "我的自定义规则",
    },
    "severity": "high",
    "description": {
        "en": "Checks for custom compliance requirement",
        "zh": "检查自定义合规要求",
    },
    "reason": {
        "en": "Resource does not meet requirement",
        "zh": "资源不符合要求",
    },
    "recommendation": {
        "en": "Configure resource properly",
        "zh": "正确配置资源",
    },
    "resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # ここにコンプライアンスロジックを記述
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SomeProperty"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    # ここにコンプライアンスチェックロジックを記述
}
```

## 主要コンポーネント

### パッケージ名

形式に従う必要があります：`infraguard.rules.<provider>.<rule_name_snake_case>`

**注意**: パッケージ名ではハイフンではなくアンダースコアを使用してください。

### ルールメタデータ

必須フィールド：
- `id`: ルール識別子（kebab-case）
- `name`: 表示名（i18nマップ）
- `severity`: `high`、`medium`、または`low`
- `description`: ルールがチェックする内容
- `reason`: 失敗した理由
- `recommendation`: 修正方法
- `resource_types`: 影響を受けるリソースタイプ（オプション）

### Denyルール

次の結果を返す必要があります：
- `id`: ルールID
- `resource_id`: テンプレートからのリソース名
- `violation_path`: 問題のあるプロパティへのパス
- `meta`: 重要度、理由、推奨事項

## ヘルパー関数

利用可能なユーティリティ関数については、[ヘルパー関数](./helper-functions)を参照してください。

## 検証

常にルールを検証してください：

```bash
infraguard policy validate my-rule.rego
```

## ルールのデバッグ

開発中にprintステートメントを使用してルールをデバッグします：

```rego
deny contains result if {
    print("Checking resource:", name)
    print("Resource properties:", object.keys(resource.Properties))
    # ここにロジックを記述
}
```

包括的なデバッグ手法については、[ポリシーのデバッグ](./debugging-policies)を参照してください。

## 次のステップ

- [ポリシーのデバッグ](./debugging-policies)を学ぶ
- [ポリシーの検証](./policy-validation)を参照
- [パックの記述](./writing-packs)を学ぶ
- [ポリシーディレクトリ構造](./policy-directory)について学ぶ
- [ヘルパー関数](./helper-functions)を探索する
