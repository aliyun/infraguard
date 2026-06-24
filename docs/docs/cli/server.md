---
title: infraguard server
---

# infraguard server

Run the InfraGuard **local web UI** as a background daemon. The server bundles a
single-page app (embedded in the binary) and a JSON API, so it works offline and
needs no extra install. See the [Web UI guide](../user-guide/web-ui) for a tour of
the pages.

## Subcommands

### start

Start the server in the background and print its URL:

```bash
infraguard server start
infraguard server start --open            # also open it in a browser
infraguard server start --port 8080
infraguard server start --foreground      # run attached (Ctrl-C to stop)
```

On start it re-execs a detached worker, records state in
`~/.infraguard/server.json`, and binds `127.0.0.1` (auto-falling back to a random
free port if the chosen one is busy).

### status

Show whether the server is running and where:

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

Stop the running server:

```bash
infraguard server stop
```

## Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--host` | Address to bind | `127.0.0.1` |
| `--port` | Port to bind (`0` = random free port) | `9527` |
| `--open` | Open the URL in a browser after starting | `false` |
| `-f, --foreground` | Run attached instead of detaching | `false` |

## Security

The server binds to loopback (`127.0.0.1`) by default and requires no
authentication for local use. If you bind to a non-loopback address
(`--host 0.0.0.0`), a random token is generated and required — it is included in
the URL printed at startup.

## API

The same capabilities are available as a JSON API under `/api` (e.g.
`POST /api/scan`, `GET /api/policies`, `GET /api/coverage`, `POST /api/rule/eval`),
with `GET /healthz` for health checks.
