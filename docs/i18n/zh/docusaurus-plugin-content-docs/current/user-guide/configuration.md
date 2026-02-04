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
infraguard config set lang en  # English（英语）
infraguard config set lang es  # Spanish（西班牙语）
infraguard config set lang fr  # French（法语）
infraguard config set lang de  # German（德语）
infraguard config set lang ja  # Japanese（日语）
infraguard config set lang pt  # Portuguese（葡萄牙语）
```

InfraGuard 支持 7 种语言：`en`、`zh`、`es`、`fr`、`de`、`ja`、`pt`。默认根据系统语言环境自动检测。

## 配置文件

配置文件位于 `~/.infraguard/config.yaml`：

```yaml
lang: zh
```

如果需要，您可以直接编辑此文件。

