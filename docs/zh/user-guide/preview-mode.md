# 预览模式

预览模式使用阿里云 ROS PreviewStack API 对模板进行验证,根据实时的云资源和配置进行合规性检查,相比静态分析提供更准确的结果。

## 概述

InfraGuard 支持两种扫描模式:

- **静态模式**(默认): 快速的本地模板语法和结构分析
- **预览模式**: 使用 ROS PreviewStack API 进行基于云端的验证

## 何时使用预览模式

在以下情况使用预览模式:

- 需要根据实际云资源配置进行验证
- 需要更准确的合规性评估

在以下情况使用静态模式:

- 快速合规性检查
- CI/CD 流水线集成(无需云凭证)

## 前置条件

预览模式需要:

1. **阿里云账号**,具有 ROS 访问权限
2. **有效凭证**(AccessKey、STS Token 或 RAM Role)
3. **网络访问** `ros.aliyuncs.com`
4. **权限**: `ros:PreviewStack` 操作权限

## 配置

### 方法 1: 环境变量(推荐)

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="****"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="****"
export ALIBABA_CLOUD_REGION_ID="cn-hangzhou"  # 可选
```

### 方法 2: Aliyun CLI 配置

```bash
# 配置 aliyun CLI
aliyun configure

# 或手动编辑 ~/.aliyun/config.json
{
  "current": "default",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "****",
      "access_key_secret": "****",
      "region_id": "cn-hangzhou"
    }
  ]
}
```

## 支持的认证方式

### AccessKey (AK/SK)

**环境变量:**
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="****"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="****"
```

**CLI 配置:**
```json
{
  "mode": "AK",
  "access_key_id": "****",
  "access_key_secret": "****"
}
```

### STS Token

**环境变量:**
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="STS.****"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="****"
export ALIBABA_CLOUD_SECURITY_TOKEN="****"
```

**CLI 配置:**
```json
{
  "mode": "StsToken",
  "access_key_id": "STS.****",
  "access_key_secret": "****",
  "sts_token": "****"
}
```

### RAM Role

**CLI 配置:**
```json
{
  "mode": "RamRoleArn",
  "access_key_id": "****",
  "access_key_secret": "****",
  "ram_role_arn": "acs:ram::****:role/RoleName",
  "ram_session_name": "session-name"
}
```

## 使用方法

### 基本用法

```bash
# 使用预览模式扫描
infraguard scan template.yaml --mode preview

# 指定策略扫描
infraguard scan template.yaml --mode preview -p pack:aliyun:quick-start-compliance-pack

# 生成 HTML 报告
infraguard scan template.yaml --mode preview --format html -o report.html
```

### 传递模板参数

```bash
# 使用键值对传递参数
infraguard scan template.yaml --mode preview \
  -i InstanceType=ecs.g6.large \
  -i ImageId=centos_7

# 从 JSON 文件传递参数
infraguard scan template.yaml --mode preview -i params.json
```

## 凭证优先级

InfraGuard 按以下顺序加载凭证:

1. **环境变量**(最高优先级)
2. **Aliyun CLI 配置**(`~/.aliyun/config.json`)

如果环境变量中找到凭证,将忽略 CLI 配置文件。

## 相关文档

- [扫描模板](scanning-templates.md)
- [管理策略](managing-policies.md)
- [CLI 参考](../cli/scan.md)
- [ROS PreviewStack API](https://www.alibabacloud.com/help/zh/ros/developer-reference/api-ros-2019-09-10-previewstack)
