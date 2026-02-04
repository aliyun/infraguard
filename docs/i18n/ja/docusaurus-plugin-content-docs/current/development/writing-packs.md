---
title: パックの記述
---

# コンプライアンスパックの記述

パックは関連するルールをグループ化して、ポリシー管理を容易にします。

## パック構造

```rego
package infraguard.packs.aliyun.my_pack

import rego.v1

pack_meta := {
    "id": "my-pack",
    "name": {
        "en": "My Compliance Pack",
        "zh": "我的合规包",
    },
    "description": {
        "en": "Collection of related rules",
        "zh": "相关规则集合",
    },
    "rules": [
        "rule-short-id-1",
        "rule-short-id-2",
        "rule-short-id-3",
    ],
}
```

## 重要なポイント

- パッケージ：`infraguard.packs.<provider>.<pack_name_snake_case>`
- 短いルールIDを使用（`rule:<provider>:`プレフィックスなし）
- 名前と説明にi18nを提供

## 場所

パックは次の場所に配置できます：
- ワークスペースローカル：`.infraguard/policies/{provider}/packs/`
- ユーザーローカル：`~/.infraguard/policies/{provider}/packs/`

ポリシー読み込み優先順位の詳細については、[ポリシーディレクトリ構造](./policy-directory)を参照してください。

## 次のステップ

- [ポリシーの検証](./policy-validation)を参照
- [ポリシーディレクトリ構造](./policy-directory)について学ぶ
- [ヘルパー関数](./helper-functions)を探索する
