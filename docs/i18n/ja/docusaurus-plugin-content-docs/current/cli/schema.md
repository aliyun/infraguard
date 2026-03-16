---
title: infraguard schema
---

# infraguard schema

LSPサーバーで使用されるROSリソースタイプスキーマを管理します。

## サブコマンド

### update

Alibaba Cloud ROS APIから最新のROSリソースタイプスキーマを取得し、ローカルに保存します：

```bash
infraguard schema update
```

## 説明

`schema`コマンドは、LSPサーバーが自動補完、検証、ホバードキュメントに使用するROSリソースタイプスキーマを管理します。スキーマには、すべてのROSリソースタイプの定義、プロパティ、型、制約が含まれています。

### 前提条件

`schema update`サブコマンドにはAlibaba Cloudの認証情報が必要です。次のいずれかの方法で設定してください：

1. **環境変数**：
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **Aliyun CLI設定**：
   ```bash
   aliyun configure
   ```

## 例

### スキーマを更新

```bash
infraguard schema update
```

出力：
```
Updating ROS resource type schema...
Schema updated successfully (350 resource types)
```

## 終了コード

- `0`: 成功
- `1`: エラー（例：認証情報の欠落、ネットワーク障害）
