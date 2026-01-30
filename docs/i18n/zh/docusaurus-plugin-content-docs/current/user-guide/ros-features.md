---
title: ROS 特性支持
---

# ROS 特性支持

InfraGuard 支持广泛的 ROS（资源编排服务）模板特性，能够对您的基础设施代码进行静态分析和验证。

## 函数

InfraGuard 支持以下 ROS 函数：

### 字符串函数
- [`Fn::Join`](https://help.aliyun.com/zh/ros/user-guide/function-join) - 使用分隔符连接字符串
- [`Fn::Sub`](https://help.aliyun.com/zh/ros/user-guide/function-sub) - 在字符串中替换变量
- [`Fn::Split`](https://help.aliyun.com/zh/ros/user-guide/function-split) - 将字符串拆分为列表
- [`Fn::Replace`](https://help.aliyun.com/zh/ros/user-guide/function-replace) - 替换文本中的字符串
- [`Fn::Str`](https://help.aliyun.com/zh/ros/user-guide/function-str) - 将值转换为字符串
- [`Fn::Indent`](https://help.aliyun.com/zh/ros/user-guide/function-indent) - 缩进文本

### 编码函数
- [`Fn::Base64Encode`](https://help.aliyun.com/zh/ros/user-guide/function-base64encode) - Base64 编码
- [`Fn::Base64Decode`](https://help.aliyun.com/zh/ros/user-guide/function-base64decode) - Base64 解码

### 列表函数
- [`Fn::Select`](https://help.aliyun.com/zh/ros/user-guide/function-select) - 从列表中选择元素
- [`Fn::Index`](https://help.aliyun.com/zh/ros/user-guide/function-index) - 查找元素的索引
- [`Fn::Length`](https://help.aliyun.com/zh/ros/user-guide/function-length) - 返回列表或字符串的长度
- [`Fn::ListMerge`](https://help.aliyun.com/zh/ros/user-guide/function-listmerge) - 合并多个列表

### 映射函数
- [`Fn::FindInMap`](https://help.aliyun.com/zh/ros/user-guide/function-findinmap) - 从映射中检索值
- [`Fn::SelectMapList`](https://help.aliyun.com/zh/ros/user-guide/function-selectmaplist) - 从映射列表中选择值
- [`Fn::MergeMapToList`](https://help.aliyun.com/zh/ros/user-guide/function-mergemaptolist) - 将映射合并到列表

### 数学函数
- [`Fn::Add`](https://help.aliyun.com/zh/ros/user-guide/function-add) - 数字相加
- [`Fn::Avg`](https://help.aliyun.com/zh/ros/user-guide/function-avg) - 计算平均值
- [`Fn::Max`](https://help.aliyun.com/zh/ros/user-guide/function-max) - 返回最大值
- [`Fn::Min`](https://help.aliyun.com/zh/ros/user-guide/function-min) - 返回最小值
- [`Fn::Calculate`](https://help.aliyun.com/zh/ros/user-guide/function-calculate) - 计算数学表达式

### 条件函数
- [`Fn::If`](https://help.aliyun.com/zh/ros/user-guide/function-if) - 根据条件返回值
- [`Fn::Equals`](https://help.aliyun.com/zh/ros/user-guide/function-equals) - 比较两个值
- [`Fn::And`](https://help.aliyun.com/zh/ros/user-guide/function-and) - 逻辑与
- [`Fn::Or`](https://help.aliyun.com/zh/ros/user-guide/function-or) - 逻辑或
- [`Fn::Not`](https://help.aliyun.com/zh/ros/user-guide/function-not) - 逻辑非
- [`Fn::Contains`](https://help.aliyun.com/zh/ros/user-guide/function-contains) - 检查值是否在列表中
- [`Fn::Any`](https://help.aliyun.com/zh/ros/user-guide/function-any) - 检查是否有任何条件为真
- [`Fn::EachMemberIn`](https://help.aliyun.com/zh/ros/user-guide/function-eachmemberin) - 检查所有元素是否在另一个列表中
- [`Fn::MatchPattern`](https://help.aliyun.com/zh/ros/user-guide/function-matchpattern) - 匹配模式

### 实用函数
- [`Fn::GetJsonValue`](https://help.aliyun.com/zh/ros/user-guide/function-getjsonvalue) - 从 JSON 中提取值
- [`Ref`](https://help.aliyun.com/zh/ros/user-guide/ref) - 引用参数和资源

## 条件

InfraGuard 完全支持 [ROS 条件](https://help.aliyun.com/zh/ros/user-guide/conditions)功能，包括：

- **条件定义** - 在 `Conditions` 部分定义条件
- **条件函数** - 在条件中使用 `Fn::Equals`、`Fn::And`、`Fn::Or`、`Fn::Not`、`Fn::If`
- **条件引用** - 在资源和输出中引用条件
- **依赖关系解析** - 自动解析条件依赖关系

## YAML 短语法

InfraGuard 支持 ROS 函数的 YAML 短语法（标签表示法）：

- `!Ref` - `Ref` 的简写形式
- `!GetAtt` - `Fn::GetAtt` 的简写形式
- 所有其他 `Fn::*` 函数都可以写作 `!FunctionName`

YAML 解析器会在模板加载时自动将这些短语法转换为标准的映射表示。

## 暂不支持的特性

InfraGuard 专注于静态分析，目前不支持以下特性：

### 运行时函数
- `Fn::GetAtt` - 需要实际创建资源后才能获取属性
- `Fn::GetAZs` - 需要运行时查询云服务商
- `Fn::GetStackOutput` - 需要访问其他资源栈的输出

### 模板部分
- `Locals` - 本地变量定义
- `Transform` - 模板转换和宏
- `Rules` - 模板验证规则
- `Mappings` - 静态值映射（不会进行策略违规分析）

### 特殊引用
- 伪参数（如 `ALIYUN::StackId`、`ALIYUN::Region` 等）- 系统提供的参数

这些特性在分析输出中会被保留原样，不会进行求值或验证。

## 相关资源

- [ROS 模板结构](https://help.aliyun.com/zh/ros/user-guide/template-structure)
- [ROS 函数](https://help.aliyun.com/zh/ros/user-guide/functions)
- [ROS 条件](https://help.aliyun.com/zh/ros/user-guide/conditions)
