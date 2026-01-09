---
title: Installation
---

# Installation

## Using go install (Recommended)

The simplest way to install InfraGuard is using `go install`:

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

This will download, compile, and install the `infraguard` binary to your `$GOPATH/bin` directory (or `$HOME/go/bin` if `GOPATH` is not set).

Make sure your Go bin directory is in your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Verify Installation

```bash
infraguard version
```

You should see the version information displayed.

## Download Pre-built Binaries

You can download pre-built binaries from [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Available Platforms

| Platform | Architecture | Filename |
|----------|-------------|----------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### Installation Steps

1. Download the appropriate binary for your platform from the [Releases page](https://github.com/aliyun/infraguard/releases)

2. Make the binary executable (Linux/macOS):

```bash
chmod +x infraguard-*
```

3. Move to a directory in your PATH:

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# Or for user-only installation
mv infraguard-* ~/bin/infraguard
```

4. Verify installation:

```bash
infraguard version
```

## Building from Source (Optional)

If you need to modify the code or prefer building from source:

### Prerequisites

- **Go 1.24.6 or later**
- **Git**
- **Make**

### Steps

```bash
# Clone the repository
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# Build the binary
make build

# Optionally install to your PATH
sudo cp infraguard /usr/local/bin/
```

## Next Steps

Now that you have InfraGuard installed, proceed to the [Quick Start Guide](./quick-start) to learn how to use it.

