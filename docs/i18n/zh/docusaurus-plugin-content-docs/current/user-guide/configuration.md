---
title: 配置
---

# 配置

InfraGuard 将配置存储在 `~/.infraguard/config.yaml` 中。

## 管理配置

### 设置值

```bash
infraguard config set lang zh
```

### 获取值

```bash
infraguard config get lang
```

### 列出所有设置

```bash
infraguard config list
```

### 取消设置值

```bash
infraguard config unset lang
```

## 可用设置

### 语言 (`lang`)

设置默认输出语言：

```bash
infraguard config set lang zh  # 中文
infraguard config set lang en  # 英文
```

## 配置文件

配置文件位于 `~/.infraguard/config.yaml`：

```yaml
lang: zh
```

如果需要，您可以直接编辑此文件。

