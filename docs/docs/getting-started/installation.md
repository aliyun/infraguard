---
title: Installation
---

# Installation

## Prerequisites

- **Go 1.24.6 or later** (for building from source)
- **Git** (for cloning the repository)

## Building from Source

Currently, InfraGuard is distributed as source code. Follow these steps to build and install:

### 1. Clone the Repository

```bash
git clone https://github.com/aliyun/infraguard.git
cd infraguard
```

### 2. Build the Binary

```bash
make build
```

This will create the `infraguard` binary in the project root.

### 3. Install to Your PATH (Optional)

You can manually copy the binary to a directory in your PATH:

```bash
# Option 1: System-wide installation (requires sudo)
sudo cp infraguard /usr/local/bin/

# Option 2: User installation (make sure ~/bin is in your PATH)
cp infraguard ~/bin/

# Option 3: Add current directory to PATH temporarily
export PATH=$PATH:$(pwd)
```

Alternatively, you can run InfraGuard directly without installing (see below).

### 4. Verify Installation

```bash
infraguard version
```

You should see the version information displayed.

## Alternative: Run Without Installing

You can also run InfraGuard directly without installing:

```bash
go run ./cmd/infraguard <command>
```

## Next Steps

Now that you have InfraGuard installed, proceed to the [Quick Start Guide](./quick-start) to learn how to use it.

