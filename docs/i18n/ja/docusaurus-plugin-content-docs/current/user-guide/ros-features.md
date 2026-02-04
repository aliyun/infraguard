---
title: ROS機能サポート
---

# ROS機能サポート

InfraGuardは、インフラストラクチャコードの静的解析と検証のために、ROS（Resource Orchestration Service）テンプレート機能の広範な範囲をサポートしています。

## 関数

InfraGuardは以下のROS関数をサポートしています：

### 文字列関数
- [`Fn::Join`](https://www.alibabacloud.com/help/en/ros/user-guide/function-join) - 区切り文字で文字列を結合
- [`Fn::Sub`](https://www.alibabacloud.com/help/en/ros/user-guide/function-sub) - 文字列内の変数を置換
- [`Fn::Split`](https://www.alibabacloud.com/help/en/ros/user-guide/function-split) - 文字列をリストに分割
- [`Fn::Replace`](https://www.alibabacloud.com/help/en/ros/user-guide/function-replace) - テキスト内の文字列を置換
- [`Fn::Str`](https://www.alibabacloud.com/help/en/ros/user-guide/function-str) - 値を文字列に変換
- [`Fn::Indent`](https://www.alibabacloud.com/help/en/ros/user-guide/function-indent) - テキストをインデント

### エンコーディング関数
- [`Fn::Base64Encode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64encode) - Base64にエンコード
- [`Fn::Base64Decode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64decode) - Base64からデコード

### リスト関数
- [`Fn::Select`](https://www.alibabacloud.com/help/en/ros/user-guide/function-select) - リストから要素を選択
- [`Fn::Index`](https://www.alibabacloud.com/help/en/ros/user-guide/function-index) - 要素のインデックスを見つける
- [`Fn::Length`](https://www.alibabacloud.com/help/en/ros/user-guide/function-length) - リストまたは文字列の長さを返す
- [`Fn::ListMerge`](https://www.alibabacloud.com/help/en/ros/user-guide/function-listmerge) - 複数のリストをマージ

### マップ関数
- [`Fn::FindInMap`](https://www.alibabacloud.com/help/en/ros/user-guide/function-findinmap) - マッピングから値を取得
- [`Fn::SelectMapList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-selectmaplist) - マップのリストから値を選択
- [`Fn::MergeMapToList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-mergemaptolist) - マップをリストにマージ

### 数学関数
- [`Fn::Add`](https://www.alibabacloud.com/help/en/ros/user-guide/function-add) - 数値を加算
- [`Fn::Avg`](https://www.alibabacloud.com/help/en/ros/user-guide/function-avg) - 平均を計算
- [`Fn::Max`](https://www.alibabacloud.com/help/en/ros/user-guide/function-max) - 最大値を返す
- [`Fn::Min`](https://www.alibabacloud.com/help/en/ros/user-guide/function-min) - 最小値を返す
- [`Fn::Calculate`](https://www.alibabacloud.com/help/en/ros/user-guide/function-calculate) - 数学式を評価

### 条件関数
- [`Fn::If`](https://www.alibabacloud.com/help/en/ros/user-guide/function-if) - 条件に基づいて値を返す
- [`Fn::Equals`](https://www.alibabacloud.com/help/en/ros/user-guide/function-equals) - 2つの値を比較
- [`Fn::And`](https://www.alibabacloud.com/help/en/ros/user-guide/function-and) - 論理AND
- [`Fn::Or`](https://www.alibabacloud.com/help/en/ros/user-guide/function-or) - 論理OR
- [`Fn::Not`](https://www.alibabacloud.com/help/en/ros/user-guide/function-not) - 論理NOT
- [`Fn::Contains`](https://www.alibabacloud.com/help/en/ros/user-guide/function-contains) - 値がリスト内にあるかチェック
- [`Fn::Any`](https://www.alibabacloud.com/help/en/ros/user-guide/function-any) - いずれかの条件が真かチェック
- [`Fn::EachMemberIn`](https://www.alibabacloud.com/help/en/ros/user-guide/function-eachmemberin) - すべての要素が別のリスト内にあるかチェック
- [`Fn::MatchPattern`](https://www.alibabacloud.com/help/en/ros/user-guide/function-matchpattern) - パターンに一致

### ユーティリティ関数
- [`Fn::GetJsonValue`](https://www.alibabacloud.com/help/en/ros/user-guide/function-getjsonvalue) - JSONから値を抽出
- [`Ref`](https://www.alibabacloud.com/help/en/ros/user-guide/ref) - パラメータとリソースを参照

## 条件

InfraGuardは[ROS Conditions](https://www.alibabacloud.com/help/ros/user-guide/conditions)機能を完全にサポートしており、以下を含みます：

- **条件定義** - `Conditions`セクションで条件を定義
- **条件関数** - 条件で`Fn::Equals`、`Fn::And`、`Fn::Or`、`Fn::Not`、`Fn::If`を使用
- **条件参照** - リソースと出力で条件を参照
- **依存関係の解決** - 条件の依存関係を自動的に解決

## YAML短縮構文

InfraGuardはROS関数のYAML短縮構文（タグ表記）をサポートしています：

- `!Ref` - `Ref`の短縮形
- `!GetAtt` - `Fn::GetAtt`の短縮形
- 他のすべての`Fn::*`関数は`!FunctionName`として記述できます

YAMLパーサーは、テンプレートの読み込み中にこれらの短縮形を標準のマップ表現に自動的に変換します。

## サポートされていない機能

InfraGuardは静的解析に焦点を当てており、現在、静的モードでは以下の機能をサポートしていません：

### ランタイム関数
- `Fn::GetAtt` - 属性を取得するために実際のリソース作成が必要
- `Fn::GetAZs` - クラウドプロバイダーへのランタイムクエリが必要
- `Fn::GetStackOutput` - 他のスタック出力へのアクセスが必要

### テンプレートセクション
- `Locals` - ローカル変数定義
- `Transform` - テンプレート変換とマクロ
- `Rules` - テンプレート検証ルール
- `Mappings` - 静的値マッピング（ポリシー違反について分析されない）

### 特別な参照
- 疑似パラメータ（例：`ALIYUN::StackId`、`ALIYUN::Region`など）- システム提供のパラメータ

これらの機能は、静的モードを使用する場合、評価や検証なしで解析出力にそのまま保持されます。

> **ヒント**: 静的解析でサポートされていない機能（`Fn::GetAtt`、`Fn::GetAZs`など）を使用するテンプレートの場合、より正確な解析のためにROS PreviewStack APIを活用する`--mode preview`の使用を推奨します。プレビューモードは実際のクラウドプロバイダーコンテキストでテンプレートを評価し、ランタイム関数やその他の動的機能のサポートを可能にします。

## 関連リソース

- [ROSテンプレート構造](https://www.alibabacloud.com/help/en/ros/user-guide/template-structure)
- [ROS関数](https://www.alibabacloud.com/help/en/ros/user-guide/functions)
- [ROS条件](https://www.alibabacloud.com/help/en/ros/user-guide/conditions)
