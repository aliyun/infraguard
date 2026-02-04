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
