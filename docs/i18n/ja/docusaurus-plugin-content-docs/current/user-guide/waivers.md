---
title: 除外
---

# 除外（Waivers、抑制）

違反が既知であり受け入れ可能な場合 — レガシーリソース、別の場所で緩和済みのリスク、一時的な例外など — ルール全体を無効化したり InfraGuard を回避したりする代わりに、その違反を**除外（waive）**できます。除外は明示的で監査可能な決定です：必ず理由を伴い、理想的には有効期限も伴います。

InfraGuard は除外された検出結果を黙って破棄することはありません。アクティブな除外はデフォルトの出力からは非表示になりますが、サマリーには集計されます。期限切れの除外は実際の違反として再び現れ、更新を促します。

## 除外する 2 つの方法

### 1. インラインコメント

テンプレート内のリソースに直接注釈を付けます。ROS（YAML）と Terraform（HCL）の両方で機能します：

```yaml
Resources:
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket, migrating 2026Q4" expires=2026-12-31
  LegacyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
```

```hcl
resource "alicloud_oss_bucket" "legacy" {
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket" expires=2026-12-31
  bucket = "legacy"
  acl    = "public-read"
}
```

構文：

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # このリソースのすべてのルールを抑制
```

リソース上またはその直前に配置されたディレクティブは、そのリソースに適用されます。`reason` のないディレクティブは無視されます。

### 2. 集中管理の除外ファイル

一括または統制された除外には、`.infraguard/waivers.yaml` をリポジトリにコミットします（他の変更と同様にコードレビューを経ます）：

```yaml
version: 1
waivers:
  - rule: oss-bucket-public-read-prohibited
    resource: "LegacyBucket"          # 正確な ID または glob、例："legacy-*"
    files: ["envs/legacy/**"]          # 任意のファイル glob（** をサポート）
    reason: "Legacy resource, approved in CAB-1234"
    expires: 2026-09-30
    owner: alice@example.com

  - rule: rds-instance-enabled-tde
    resource: "*"                      # 一致するすべてのリソース
    files: ["sandbox/**"]
    reason: "Sandbox environment does not require TDE"
    # expires なし → 永続的な除外（`waiver lint` で警告される）
```

| フィールド | 意味 | 必須 |
| --- | --- | --- |
| `rule` | 短いルール ID、またはすべてのルールを表す `*` | はい |
| `resource` | リソース ID、正確な値または glob | いいえ（任意のリソース） |
| `files` | ファイルパスの glob（`*`、`**`） | いいえ（任意のファイル） |
| `reason` | 正当化理由 | はい |
| `expires` | `YYYY-MM-DD`。空の場合は永続的 | いいえ（推奨） |
| `owner` | 担当者 | いいえ（推奨） |

同じリソースに対しては、インラインディレクティブがファイル除外よりも優先されます。

## スキャン中の動作

- **アクティブ**な除外 → 違反は非表示になり、サマリーでは `waived` として集計されます。
- **期限切れ**の除外 → 違反が再び表示され、デフォルトではビルドを失敗させます。
- **除外なし** → 通常の違反。

```bash
infraguard scan -p pack:aliyun:... template.yaml          # 除外は自動的に適用される
infraguard scan ... --show-waived template.yaml           # 除外された内容を表示
infraguard scan ... --no-waivers template.yaml            # 全体を表示し、すべての除外を無視
infraguard scan ... --fail-on-expired=false template.yaml # 期限切れの除外で失敗させない
```

CI では、セキュリティチームが `--no-waivers` を実行して全体像を把握することも、除外を維持しつつデフォルトの `--fail-on-expired` に依存して更新を強制することもできます。

## 除外の統制

```bash
infraguard waiver list    # すべての除外とそのステータスを表示
infraguard waiver lint    # 理由の欠落、不明なルール、期限切れのエントリを検出
```

除外ファイル自体を健全に保つため、`waiver lint` を pre-commit または CI に追加してください。[waiver CLI リファレンス](../cli/waiver) を参照してください。

## 安全性に関する注意

除外は正当な目的でリスクを隠すため、意図的に制約されています：`reason` は必須であり、期限切れの除外はデフォルトで失敗し、JSON 出力には監査のために除外された項目が常に保持され、ファイルは Git を通じてレビューされます。広範な除外よりも狭い除外（ルール + リソース + ファイル）を優先し、常に `expires` 日付を設定してください。
