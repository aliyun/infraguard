---
title: 常见问题
---

# 常见问题

## 一般问题

### 什么是 InfraGuard？

InfraGuard 是一个命令行工具，在部署前根据合规策略验证基础设施即代码 (IaC) 模板。它有助于在开发周期的早期发现安全和合规问题。

### 支持哪些云服务商？

目前，InfraGuard 支持阿里云 (Aliyun) ROS 模板。未来版本可能会添加对其他云服务商的支持。

### InfraGuard 是免费的吗？

是的，InfraGuard 是开源的，并在 Apache License 2.0 下发布。

## 使用

### 如何扫描模板？

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

有关更多示例，请参阅[快速入门指南](./getting-started/quick-start)。

### 我可以在一次扫描中使用多个策略吗？

可以！使用多个 `-p` 选项：

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### 有哪些输出格式可用？

InfraGuard 支持三种格式：
- **表格**：彩色控制台输出（默认）
- **JSON**：用于 CI/CD 的机器可读格式
- **HTML**：交互式报告

### 如何更改语言？

使用 `--lang` 选项或永久设置：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang zh
# 或永久设置
infraguard config set lang zh
```

## 策略

### 策略存储在哪里？

策略嵌入在二进制文件中。您也可以将自定义策略存储在 `~/.infraguard/policies/` 中。

### 如何更新策略？

```bash
infraguard policy update
```

### 我可以编写自定义策略吗？

可以！策略使用 Rego（Open Policy Agent 语言）编写。请参阅[开发指南](./development/writing-rules)。

### 如何验证我的自定义策略？

```bash
infraguard policy validate my-rule.rego
```

### 如何调试我的策略？

有两种方式：

**1. 使用 Print 语句：**

```rego
deny contains result if {
    print("检查资源:", name)
    print("属性:", object.keys(resource.Properties))
    # 您的策略逻辑
}
```

输出将显示在标准错误流（stderr）中并包含文件位置。

**2. 使用 VSCode 调试器：**

- 安装 [OPA](https://www.openpolicyagent.org/docs#1-download-opa)、[Regal](https://www.openpolicyagent.org/projects/regal#download-regal) 和 [VSCode OPA 插件](https://marketplace.visualstudio.com/items?itemName=tsandall.opa)
- 创建 `input.json` 测试数据文件
- 点击行号设置断点
- 按 F5 开始调试

有关完整指南，请参阅[调试策略](./development/debugging-policies)。

## 故障排除

### 命令未找到：infraguard

确保 `infraguard` 二进制文件在您的 PATH 中。使用 `make build` 构建后，您可以：

1. 将二进制文件复制到 PATH 中的目录：
   ```bash
   sudo cp infraguard /usr/local/bin/
   # 或
   cp infraguard ~/bin/  # 确保 ~/bin 在您的 PATH 中
   ```

2. 或临时将当前目录添加到 PATH：
   ```bash
   export PATH=$PATH:$(pwd)
   ```

3. 或直接运行 InfraGuard 而无需安装：
   ```bash
   ./infraguard <command>
   ```

### 策略未找到

使用 `infraguard policy list` 查看所有可用策略。确保您使用正确的格式：`rule:provider:name` 或 `pack:provider:name`。

### 模板解析错误

确保您的模板是有效的 YAML 或 JSON。检查语法错误。

### 未发现违规但预期有违规

验证：
1. 策略适用于您模板中的资源
2. 策略 ID 正确
3. 您的模板确实存在策略检查的问题

## CI/CD 集成

### 如何在 CI/CD 中使用 InfraGuard？

使用 JSON 输出并检查退出代码：

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
EXIT_CODE=$?
if [ $EXIT_CODE -eq 2 ]; then
  echo "发现高严重性违规"
  exit 1
fi
```

### 退出代码是什么？

- `0`: 无违规
- `1`: 发现违规
- `2`: 发现高严重性违规

## 贡献

### 如何贡献？

欢迎贡献！您可以：
- 报告错误
- 提交功能请求
- 贡献策略
- 改进文档

访问我们的 [GitHub 仓库](https://github.com/aliyun/infraguard) 开始。

### 如何报告错误？

在 [GitHub Issues](https://github.com/aliyun/infraguard/issues) 上创建问题，包括：
- InfraGuard 版本（`infraguard version`）
- 重现步骤
- 预期与实际行为
- 模板和策略（如果适用）

## 还有其他问题？

如果这里没有回答您的问题，请：
1. 查看[文档](./intro)
2. 搜索现有的 [GitHub Issues](https://github.com/aliyun/infraguard/issues)
3. 如有需要，创建新问题

