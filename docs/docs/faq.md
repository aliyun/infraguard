---
title: FAQ
---

# Frequently Asked Questions

## General

### What is InfraGuard?

InfraGuard is a command-line tool that validates Infrastructure as Code (IaC) templates against compliance policies before deployment. It helps catch security and compliance issues early in the development cycle.

### Which cloud providers are supported?

Currently, InfraGuard supports Alibaba Cloud (Aliyun) ROS templates. Support for other providers may be added in future versions.

### Is InfraGuard free to use?

Yes, InfraGuard is open source and released under the Apache License 2.0.

## Usage

### How do I scan a template?

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

See the [Quick Start Guide](./getting-started/quick-start) for more examples.

### Can I use multiple policies in one scan?

Yes! Use multiple `-p` flags:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### What output formats are available?

InfraGuard supports three formats:
- **Table**: Colored console output (default)
- **JSON**: Machine-readable for CI/CD
- **HTML**: Interactive report

### How do I change the language?

Use the `--lang` flag or set it permanently:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang zh
# Or set permanently
infraguard config set lang zh
```

## Policies

### Where are policies stored?

Policies are embedded in the binary. You can also store custom policies in `~/.infraguard/policies/`.

### How do I update policies?

```bash
infraguard policy update
```

### Can I write custom policies?

Yes! Policies are written in Rego (Open Policy Agent language). See the [Development Guide](./development/writing-rules).

### How do I validate my custom policy?

```bash
infraguard policy validate my-rule.rego
```

## Troubleshooting

### Command not found: infraguard

Make sure the `infraguard` binary is in your PATH. After building with `make build`, you can:

1. Copy the binary to a directory in your PATH:
   ```bash
   sudo cp infraguard /usr/local/bin/
   # or
   cp infraguard ~/bin/  # Make sure ~/bin is in your PATH
   ```

2. Or add the current directory to your PATH temporarily:
   ```bash
   export PATH=$PATH:$(pwd)
   ```

3. Or run InfraGuard directly without installing:
   ```bash
   ./infraguard <command>
   ```

### Policy not found

Use `infraguard policy list` to see all available policies. Ensure you're using the correct format: `rule:provider:name` or `pack:provider:name`.

### Template parsing error

Ensure your template is valid YAML or JSON. Check for syntax errors.

### No violations found but expected some

Verify:
1. The policy applies to resources in your template
2. The policy ID is correct
3. Your template actually has the issue the policy checks for

## CI/CD Integration

### How do I use InfraGuard in CI/CD?

Use JSON output and check exit codes:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
EXIT_CODE=$?
if [ $EXIT_CODE -eq 2 ]; then
  echo "High severity violations found"
  exit 1
fi
```

### What are the exit codes?

- `0`: No violations
- `1`: Violations found
- `2`: High severity violations found

## Contributing

### How can I contribute?

Contributions are welcome! You can:
- Report bugs
- Submit feature requests
- Contribute policies
- Improve documentation

Visit our [GitHub repository](https://github.com/aliyun/infraguard) to get started.

### How do I report a bug?

Create an issue on [GitHub Issues](https://github.com/aliyun/infraguard/issues) with:
- InfraGuard version (`infraguard version`)
- Steps to reproduce
- Expected vs actual behavior
- Template and policy (if applicable)

## Still Have Questions?

If your question isn't answered here, please:
1. Check the [documentation](./intro)
2. Search existing [GitHub Issues](https://github.com/aliyun/infraguard/issues)
3. Create a new issue if needed

