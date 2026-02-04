---
title: ポリシーのデバッグ
---

# Regoポリシーのデバッグ

Regoポリシーをデバッグするには2つの方法があります：printステートメントを使用するか、VSCodeデバッガーを使用します。

## 方法1：Printステートメントの使用

### 基本的な使用方法

Regoポリシーの任意の場所に`print()`ステートメントを追加します：

```rego
package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

deny contains result if {
    print("Starting policy evaluation")
    
    some name, resource in helpers.resources_by_types(rule_meta.resource_types)
    print("Checking resource:", name)
    print("Resource type:", resource.Type)
    
    not is_compliant(resource)
    print("Found violation for resource:", name)
    
    result := {...}
}
```

### 出力形式

Printステートメントはファイル位置とともにstderrに出力します：

```
/path/to/policy.rego:42: Starting policy evaluation
/path/to/policy.rego:45: Checking resource: MyBucket
/path/to/policy.rego:46: Resource type: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: Found violation for resource: MyBucket
```

### 一般的な使用例

**入力データの検査:**
```rego
print("Input keys:", object.keys(input))
print("Template version:", input.ROSTemplateFormatVersion)
print("Number of resources:", count(input.Resources))
```

**リソース反復のデバッグ:**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("Resource:", name)
print("Properties:", object.keys(resource.Properties))
```

**条件のチェック:**
```rego
condition1 := some_check(resource)
print("Condition 1 result:", condition1)
```

**変数の検査:**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("Property value:", property)
print("Property type:", type_name(property))
```

## 方法2：VSCodeデバッガーの使用

VSCodeは、ブレークポイント、変数の検査、ステップ実行を備えたより強力なデバッグ体験を提供します。

### 前提条件

1. **OPAのインストール**

   公式サイトからOPAをダウンロードしてインストール：
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **Regalのインストール**

   Rego開発を強化するためにRegalをインストール：
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **VSCode OPA拡張機能のインストール**

   VSCodeマーケットプレイスから公式OPA拡張機能をインストール：
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### セットアップ手順

1. **テスト入力の準備**

   ポリシーディレクトリに`input.json`という名前のファイルを作成し、テストデータを追加：

   ```json
   {
     "ROSTemplateFormatVersion": "2015-09-01",
     "Resources": {
       "MyBucket": {
         "Type": "ALIYUN::OSS::Bucket",
         "Properties": {
           "BucketName": "test-bucket",
           "AccessControl": "private"
         }
       }
     }
   }
   ```

2. **ブレークポイントの設定**

   VSCodeで`.rego`ポリシーファイルを開き、実行を一時停止したい場所の左マージンをクリックしてブレークポイントを設定します。

3. **デバッグの開始**

   - `F5`を押すか、実行 → デバッグの開始に移動
   - デバッガーはブレークポイントで一時停止します
   - 変数を検査し、コードをステップ実行し、式を評価できます

## 方法の選択

- **Printステートメント**: 迅速で簡単、あらゆる環境で動作、本番環境でのデバッグに有用
- **VSCodeデバッガー**: より強力、完全な変数検査を備えたインタラクティブなデバッグ、開発に最適

両方の方法を組み合わせて使用できます：迅速なチェックにはprintステートメントを使用し、詳細な調査にはデバッガーを使用します。
