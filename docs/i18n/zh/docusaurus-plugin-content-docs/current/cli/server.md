---
title: infraguard server
---

# infraguard server

以**后台守护进程**方式运行 InfraGuard 的本地 Web 界面。服务端内置了单页应用（已打包进二进制）和 JSON API，离线可用、无需额外安装。各页面介绍见 [Web 界面指南](../user-guide/web-ui)。

## 子命令

### start

后台启动服务并打印访问地址：

```bash
infraguard server start
infraguard server start --open            # 启动后在浏览器中打开
infraguard server start --port 8080
infraguard server start --foreground      # 前台运行（Ctrl-C 退出）
```

启动时会 re-exec 一个分离的工作进程，将状态写入 `~/.infraguard/server.json`，并绑定 `127.0.0.1`（若端口被占用则自动回退到随机空闲端口）。

### status

查看服务是否在运行及其地址：

```bash
infraguard server status
```

```
Server is running.
  URL:     http://127.0.0.1:9527
  PID:     12345
  Uptime:  3m20s
  Version: 0.9.0
```

### stop

停止正在运行的服务：

```bash
infraguard server stop
```

## 参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `--host` | 绑定地址 | `127.0.0.1` |
| `--port` | 绑定端口（`0` = 随机空闲端口） | `9527` |
| `--open` | 启动后在浏览器中打开 | `false` |
| `-f, --foreground` | 前台运行而非分离后台 | `false` |

## 安全

服务默认绑定到环回地址（`127.0.0.1`），本地使用无需鉴权。若绑定到非环回地址（`--host 0.0.0.0`），会生成并要求一个随机 token——它会包含在启动时打印的 URL 中。

## API

同样的能力以 JSON API 形式暴露在 `/api` 下（如 `POST /api/scan`、`GET /api/policies`、`GET /api/coverage`、`POST /api/rule/eval`），并提供 `GET /healthz` 用于健康检查。
