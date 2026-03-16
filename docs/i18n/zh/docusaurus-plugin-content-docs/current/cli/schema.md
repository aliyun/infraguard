---
title: infraguard schema
---

# infraguard schema

管理 LSP 服务器使用的 ROS 资源类型 Schema。

## 子命令

### update

从阿里云 ROS API 获取最新的 ROS 资源类型 Schema 并保存到本地：

```bash
infraguard schema update
```

## 说明

`schema` 命令管理 LSP 服务器用于自动补全、验证和悬停文档的 ROS 资源类型 Schema。该 Schema 包含所有 ROS 资源类型的定义、属性、类型和约束。

### 前提条件

`schema update` 子命令需要阿里云凭证。可通过以下方式之一配置：

1. **环境变量**：
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **阿里云 CLI 配置**：
   ```bash
   aliyun configure
   ```

## 示例

### 更新 Schema

```bash
infraguard schema update
```

输出：
```
正在更新 ROS 资源类型 Schema...
Schema 更新成功（350 个资源类型）
```

## 退出代码

- `0`: 成功
- `1`: 错误（例如：缺少凭证、网络故障）
