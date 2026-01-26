---
title: 调试策略
---

# 调试 Rego 策略

有两种方式可以调试 Rego 策略：使用 print 语句或使用 VSCode 调试器。

## 方法一：使用 Print 语句

### 基本用法

在 Rego 策略中的任何位置添加 `print()` 语句：

```rego
package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

deny contains result if {
    print("开始策略评估")
    
    some name, resource in helpers.resources_by_types(rule_meta.resource_types)
    print("检查资源:", name)
    print("资源类型:", resource.Type)
    
    not is_compliant(resource)
    print("发现资源违规:", name)
    
    result := {...}
}
```

### 输出格式

Print 语句会输出到标准错误流（stderr），并包含文件位置信息：

```
/path/to/policy.rego:42: 开始策略评估
/path/to/policy.rego:45: 检查资源: MyBucket
/path/to/policy.rego:46: 资源类型: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: 发现资源违规: MyBucket
```

### 常见使用示例

**检查输入数据：**
```rego
print("输入数据键:", object.keys(input))
print("模板版本:", input.ROSTemplateFormatVersion)
print("资源数量:", count(input.Resources))
```

**调试资源遍历：**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("资源:", name)
print("属性:", object.keys(resource.Properties))
```

**检查条件判断：**
```rego
condition1 := some_check(resource)
print("条件 1 结果:", condition1)
```

**检查变量：**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("属性值:", property)
print("属性类型:", type_name(property))
```

## 方法二：使用 VSCode 调试器

VSCode 提供了更强大的调试体验，支持断点、变量检查和逐步执行。

### 前置要求

1. **安装 OPA**

   从官方网站下载并安装 OPA：
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **安装 Regal**

   安装 Regal 以增强 Rego 开发体验：
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **安装 VSCode OPA 插件**

   从 VSCode 市场安装官方 OPA 扩展：
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### 设置步骤

1. **准备测试输入**

   在策略目录中创建名为 `input.json` 的文件，包含测试数据：

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

2. **设置断点**

   在 VSCode 中打开 `.rego` 策略文件，点击左侧边距设置断点。

3. **开始调试**

   - 按 `F5` 或选择 运行 → 启动调试
   - 调试器会在断点处暂停执行
   - 您可以检查变量、逐步执行代码和评估表达式

## 选择调试方法

- **Print 语句**：快速简单，适用于任何环境，适合生产环境调试
- **VSCode 调试器**：更强大，交互式调试，完整的变量检查，更适合开发环境

您可以同时使用两种方法：使用 print 语句进行快速检查，使用调试器进行深入调查。
