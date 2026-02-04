---
title: ポリシーの検証
---

# ポリシーの検証

カスタムポリシーを使用する前に検証してください。

## 検証コマンド

```bash
infraguard policy validate <path>
```

## 検証される内容

- Rego構文
- 必要なメタデータ（`rule_meta`または`pack_meta`）
- 適切なdenyルール構造
- i18n文字列形式

## 例

```bash
# 単一ファイルを検証
infraguard policy validate rule.rego

# ディレクトリを検証
infraguard policy validate ./policies/

# 言語オプション付き
infraguard policy validate rule.rego --lang ja
```

詳細については、[ポリシーの管理](../user-guide/managing-policies)を参照してください。
