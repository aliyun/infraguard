---
title: 快速入门
---

# 快速入门

本指南将帮助您在几分钟内开始使用 InfraGuard。

## 步骤 1：创建示例 ROS 模板

创建一个名为 `template.yaml` 的文件，内容如下：

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: Sample ECS instance

Resources:
  MyECS:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      ImageId: 'centos_7'
      InstanceType: 'ecs.t5-lc1m1.small'
      AllocatePublicIP: true
      SecurityGroupId: 'sg-xxxxx'
      VpcId: 'vpc-xxxxx'
      VSwitchId: 'vsw-xxxxx'
```

## 步骤 2：运行第一次扫描

使用内置规则扫描模板：

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

您应该看到输出显示 ECS 实例分配了公网 IP，这是一个安全问题。

## 步骤 3：使用合规包

除了单个规则，您可以使用整个合规包进行扫描：

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## 步骤 4：生成报告

InfraGuard 支持多种输出格式：

### 表格格式（默认）

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### JSON 格式

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### HTML 报告

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

在浏览器中打开 `report.html` 查看交互式报告。

## 步骤 5：列出可用策略

查看所有可用的规则和包：

```bash
# 列出所有策略
infraguard policy list

# 获取特定规则的详细信息
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# 获取合规包的详细信息
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## 常见用例

### 使用多个策略扫描

您可以在一次扫描中应用多个策略：

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### 设置语言偏好

InfraGuard 支持 7 种语言：

```bash
# 中文输出
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang zh

# 英文输出
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# 其他支持的语言：es（西班牙语）、fr（法语）、de（德语）、ja（日语）、pt（葡萄牙语）
```

您也可以永久设置语言：

```bash
infraguard config set lang zh
```

支持的语言代码：`en`、`zh`、`es`、`fr`、`de`、`ja`、`pt`。默认根据系统语言环境自动检测。

## 下一步

- **了解更多**：阅读[用户指南](../user-guide/scanning-templates)获取详细信息
- **探索策略**：浏览[策略参考](../policies/aliyun/rules)查看所有可用的规则和包
- **编写自定义策略**：查看[开发指南](../development/writing-rules)创建您自己的规则

## 获取帮助

如果遇到任何问题：

1. 查看 [FAQ](../faq) 页面
2. 仔细查看错误消息 - 它们通常包含有用的提示
3. 在 [GitHub](https://github.com/aliyun/infraguard/issues) 上报告问题

