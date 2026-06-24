---
title: Web 界面
---

# Web 界面

InfraGuard 自带一个本地 Web 界面，适合更喜欢图形化操作的用户。它由二进制本身提供服务——无需安装、无需后端、完全离线。

```bash
infraguard server start --open
```

该命令会后台启动一个绑定到 `127.0.0.1` 的服务，打印访问地址并在浏览器中打开。用 `infraguard server status` 和 `infraguard server stop` 管理它（详见 [server 命令参考](../cli/server)）。

## 页面

### 扫描

粘贴阿里云 ROS 或 Terraform 模板，选择要应用的策略（或保持「全部」），点击扫描。结果以按严重程度排序的卡片展示，包含规则、资源、源码行号与修复建议。点击严重级别芯片可筛选。

### 策略

浏览内置规则与合规包：

- **总览** —— 总数、严重程度分布、按服务的覆盖情况。
- **合规包** / **规则** —— 可搜索，支持按产品与资源类型筛选。

点击任意规则可查看其元数据与 Rego 实现（ROS / Terraform）。

### 规则工作台

编写 Rego 规则并对模板即时评估，或用合规/违规夹具进行测试——与 CLI 相同的引擎，在浏览器中运行。

## 浏览器 Playground

如果想零安装快速体验，文档站还提供一个 [Playground](/playground)，可完全在浏览器中扫描 ROS 模板。它覆盖快速体验规则集；完整规则目录与 Terraform 支持请使用 `infraguard server`。
