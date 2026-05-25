---
title: Policy Directory Structure
---

# Policy Directory Structure

InfraGuard supports multiple policy sources with a clear priority system for loading policies.

## Directory Structure

### Standard Policy Directory Structure

Policies follow a provider-first directory structure:

```
{policy-root}/
├── {provider}/
│   ├── rules/
│   │   ├── ros/
│   │   │   ├── rule1.rego        # ROS rules
│   │   │   └── rule2.rego
│   │   └── terraform/
│   │       ├── rule1.rego        # Terraform rules
│   │       └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # Compliance packs
│       └── pack2.rego
```

**Example:**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── ros/
│   │   │   ├── metadata-ros-composer-check.rego
│   │   │   ├── metadata-templatetags-check.rego
│   │   │   └── parameter-sensitive-noecho-check.rego
│   │   └── terraform/
│   │       └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

The `ros/` and `terraform/` subdirectories are optional for custom policy sets, but recommended. InfraGuard uses them to detect which IaC type a rule applies to and filters policies automatically during scans.

## Policy Loading Priority

InfraGuard loads policies from multiple sources with the following priority (highest to lowest):

1. **Workspace-local policies**: `.infraguard/policies/` (current working directory)
2. **User-local policies**: `~/.infraguard/policies/` (user home directory)
3. **Embedded policies**: Built into the binary

Policies with the same ID from higher-priority sources will override those from lower-priority sources.

## Workspace-Local Policies

Workspace-local policies are stored in the `.infraguard/policies/` directory within your current working directory. This is the highest priority location and is ideal for:

- Project-specific custom rules and packs
- Overriding built-in policies for specific projects
- Testing new policies before promoting them to user-local or embedded

### Using Workspace Policies

1. Create the directory structure:

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. Add your custom rules or packs to the appropriate directories

3. List available policies:

```bash
infraguard policy list
```

Your workspace policies will appear with the ID format: `rule:myprovider:rule-name` or `pack:myprovider:pack-name`

4. Use them in scans:

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## User-Local Policies

User-local policies are stored in `~/.infraguard/policies/` in your home directory. These policies are available across all projects for your user account.

## ID Generation

InfraGuard automatically generates policy IDs based on directory structure:

- **Rules**: `rule:{provider}:{rule-id}`
- **Packs**: `pack:{provider}:{pack-id}`

Where `{provider}` is derived from the parent directory name (e.g., `solution`, `aliyun`, `custom`).

IaC type subdirectories such as `ros/` and `terraform/` are excluded from generated IDs, so these files both produce `rule:aliyun:ecs-instance-no-public-ip`:

```
aliyun/rules/ros/ecs-instance-no-public-ip.rego
aliyun/rules/terraform/ecs-instance-no-public-ip.rego
```

## Next Steps

- Learn to [Write Rules](./writing-rules)
- Learn to [Write Packs](./writing-packs)
- See [Policy Validation](./policy-validation)
