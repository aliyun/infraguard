# InfraGuard Project

## Overview

InfraGuard is an Infrastructure as Code (IaC) compliance pre-check CLI tool designed for Alibaba Cloud (Aliyun) Resource
Orchestration Service (ROS) templates. It evaluates IaC templates against compliance policies written in Rego (Open
Policy Agent) before deployment.

## Tech Stack

| Component        | Technology              | Version/Notes                   |
|------------------|-------------------------|---------------------------------|
| Language         | Go                      | 1.24.6                          |
| CLI Framework    | Cobra                   | spf13/cobra                     |
| Policy Engine    | Open Policy Agent (OPA) | Rego language                   |
| Policy Download  | go-getter               | Supports git, HTTP, S3, etc.    |
| Template Parsing | YAML/JSON               | gopkg.in/yaml.v3, encoding/json |
| Locale Detection | go-locale               | Xuanwo/go-locale                |
| Table Rendering  | tablewriter             | olekukonko/tablewriter          |
| Testing          | GoConvey                | smartystreets/goconvey          |

## Project Structure

```
infraguard/
├── cmd/infraguard/          # CLI entry point and commands
│   └── cmd/
│       ├── root.go          # Root command with i18n setup
│       ├── scan.go          # Template scanning command
│       ├── policy.go        # Policy management commands
│       └── version.go       # Version command
├── pkg/                     # Core packages
│   ├── auth/                # Aliyun credentials handling
│   ├── engine/              # OPA/Rego evaluation engine
│   ├── i18n/                # Internationalization support
│   │   └── locales/         # en.yaml, zh.yaml
│   ├── loader/              # Template file loading
│   ├── mapper/              # Violation to source mapping
│   ├── models/              # Core data structures
│   ├── policy/              # Policy discovery and management
│   └── reporter/            # Output rendering (table, JSON, HTML)
├── policies/                # Embedded policy library
│   ├── aliyun/              # Provider-specific policies
│   │   ├── rules/           # Individual compliance rules
│   │   ├── packs/           # Rule groupings (packs)
│   │   └── lib/             # Helper rego functions
│   └── testdata/            # Test data
│       └── aliyun/          # Provider-specific test data
│           ├── rules/       # Rule test cases
│           └── packs/       # Pack test cases
├── openspec/                # Specifications and changes
│   ├── specs/               # Current capability specs
│   └── changes/             # Change proposals
└── testdata/                # Test fixtures
```

## Key Concepts

### Rules

Individual compliance checks defined in `.rego` files with embedded metadata:

- ID format: `rule:<provider>:<name>` (e.g., `rule:aliyun:ecs-public-ip`)
- Metadata includes: name, severity, description, reason, recommendation, resource_types
- All text fields support i18n (English and Chinese)

### Packs

Collections of related rules:

- ID format: `pack:<provider>:<name>` (e.g., `pack:aliyun:multi-zone-best-practice`)
- Reference multiple rule IDs
- Support i18n for name and description

### Severity Levels

- `high` - Critical security or compliance issues
- `medium` - Important but less urgent issues
- `low` - Best practice suggestions

## CLI Commands

| Command                                  | Description                                                      |
|------------------------------------------|------------------------------------------------------------------|
| `infraguard scan <template>`             | Scan IaC template for violations                                 |
| `infraguard scan <template> -p <policy>` | Scan with specific policy (rule ID, pack ID, file, or directory) |
| `infraguard policy update`               | Download/update policy library                                   |
| `infraguard policy list`                 | List available rules and packs                                   |
| `infraguard policy get <ID>`             | Show details of a rule or pack                                   |
| `infraguard policy validate <path>`      | Validate policy files against InfraGuard schema                  |
| `infraguard policy format <path>`        | Format policy files using OPA formatter                          |
| `infraguard config set <key> <value>`    | Set a configuration value                                        |
| `infraguard config get <key>`            | Get a configuration value                                        |
| `infraguard config unset <key>`          | Remove a configuration value                                     |
| `infraguard config list`                 | List all configuration values                                    |

### Policy Validate Options

- `--lang <en|zh>` - Output language (default: auto-detect)

### Policy Format Options

- `--write` - Write formatted content back to files
- `--diff` - Show diff of changes
- `--lang <en|zh>` - Output language (default: auto-detect)

### Output Formats

- `table` (default) - Colored terminal table
- `json` - Machine-readable JSON
- `html` - Interactive HTML report

## Conventions

### Code Style

- All code, logs, and error messages in **English**
- Cursor/AI conversations in **Chinese** (workspace rule)
- Follow standard Go conventions (`gofmt`, `go vet`)
- Use GoConvey for BDD-style tests

### Internationalization (i18n)

- All user-facing text MUST support i18n
- Supported languages: English (`en`), Chinese (`zh`)
- Locale files in `pkg/i18n/locales/`
- Language resolution priority (highest to lowest):
    1. `--lang` command-line flag
    2. `lang` value from `~/.infraguard/config.yaml`
    3. Auto-detect system language
- Policy metadata uses map format: `{"en": "...", "zh": "..."}`

### Configuration

- Configuration file: `~/.infraguard/config.yaml`
- Manage with `infraguard config` command
- Available configuration keys:
    - `lang`: Output language (`en` or `zh`)

### Policy Authoring

#### Rule Package Structure

- Package format: `infraguard.rules.<provider>.<rule_name_snake_case>` (e.g.,
  `package infraguard.rules.aliyun.ecs_no_public_ip`)
- **Note**: Hyphens (`-`) are NOT allowed in package names and MUST be replaced with underscores (`_`).
- Import `rego.v1` for modern Rego syntax
- Import `data.infraguard.helpers` for helper functions
- **Note**: Only files with `package infraguard.rules.*` will be recognized as rules by `policy validate`

#### Rule ID Format

- Rules: `rule:<provider>:<name>` (e.g., `rule:aliyun:ecs-no-public-ip`)
- Packs: `pack:<provider>:<name>` (e.g., `pack:aliyun:security-baseline`)

#### Rule Metadata (`rule_meta`)

Required fields:

```rego
rule_meta := {
    "id": "rule:aliyun:example-rule",
    "name": {"en": "...", "zh": "..."},
    "severity": "high|medium|low",
    "description": {"en": "...", "zh": "..."},
    "reason": {"en": "...", "zh": "..."},
    "recommendation": {"en": "...", "zh": "..."},
    "resource_types": ["ALIYUN::ECS::Instance"],
}
```

#### Violation Entry Point

- Use `deny contains result if { ... }` to generate violations
- Each result must include:
    - `id`: Full rule ID (e.g., `rule:aliyun:ecs-no-public-ip`)
    - `resource_id`: Resource name from template
    - `violation_path`: Property path array for source location (e.g., `["Properties", "AllocatePublicIP"]`)
    - `meta`: Object with `severity`, `reason`, `recommendation`

Example:

```rego
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    resource.Properties.AllocatePublicIP == true
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "AllocatePublicIP"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}
```

#### Helper Functions (`data.infraguard.helpers`)

| Function                                | Description                              |
|-----------------------------------------|------------------------------------------|
| `resources_by_type(type)`               | Get resources as `{name: resource}` map  |
| `resource_names_by_type(type)`          | Get resource names as list               |
| `count_resources_by_type(type)`         | Count resources of type                  |
| `resource_exists(type)`                 | Check if resource type exists            |
| `has_property(resource, prop)`          | Check if property exists and is not null |
| `get_property(resource, prop, default)` | Get property with default                |
| `is_true(v)` / `is_false(v)`            | Check boolean (handles string)           |
| `is_public_cidr(cidr)`                  | Check if CIDR is `0.0.0.0/0` or `::/0`   |
| `includes(list, elem)`                  | Check if element in list                 |

#### Rule File Template

```rego
# Rule description
# Brief explanation of what this rule checks.
package infraguard.rules.<provider>.<rule_name_snake_case>

import rego.v1

import data.infraguard.helpers

rule_meta := {
    "id": "rule:<provider>:<rule-name>",
    "name": {"en": "...", "zh": "..."},
    "severity": "medium",
    "description": {"en": "...", "zh": "..."},
    "reason": {"en": "...", "zh": "..."},
    "recommendation": {"en": "...", "zh": "..."},
    "resource_types": ["ALIYUN::XXX::YYY"],
}

# Helper function for compliance check
is_compliant(resource) if {
    # compliance logic
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::XXX::YYY")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SomeProperty"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}
```

#### Pack Authoring

Packs group related rules together for easier policy management.

##### Pack Package Structure

- Package format: `infraguard.packs.<provider>.<pack_name_snake_case>` (e.g.,
  `package infraguard.packs.aliyun.security_group_best_practice`)
- **Note**: Hyphens (`-`) are NOT allowed in package names and MUST be replaced with underscores (`_`).
- Location: `policies/<provider>/packs/<pack-name>.rego`
- **Note**: Only files with `package infraguard.packs.*` will be recognized as packs by `policy validate`

##### Pack Metadata (`pack_meta`)

Required fields:

```rego
pack_meta := {
    "id": "pack:<provider>:<pack-name>",
    "name": {"en": "...", "zh": "..."},
    "description": {"en": "...", "zh": "..."},
    "rules": [
        "<rule-short-id-1>",
        "<rule-short-id-2>",
    ],
}
```

Note: `rules` uses short rule IDs (e.g., `"ecs-no-public-ip"`) without the `rule:<provider>:` prefix.

##### Pack File Template

```rego
# Pack description
# Brief explanation of what this pack covers.
package infraguard.packs.<provider>.<pack_name_snake_case>

import rego.v1

pack_meta := {
    "id": "pack:<provider>:<pack-name>",
    "name": {
        "en": "Pack Display Name",
        "zh": "合规包显示名称",
    },
    "description": {
        "en": "Description of what this pack checks.",
        "zh": "此合规包检查内容的描述。",
    },
    "rules": [
        "rule-short-id-1",
        "rule-short-id-2",
        "rule-short-id-3",
    ],
}
```

##### Pack Example

```rego
# Security Group Best Practice Pack
# Continuously check security group rules for compliance and reduce security risks.
package infraguard.packs.aliyun.security_group_best_practice

import rego.v1

pack_meta := {
    "id": "security-group-best-practice",
    "name": {
        "en": "Security Group Best Practice",
        "zh": "安全组最佳实践",
    },
    "description": {
        "en": "Continuously check security group rules for compliance and reduce security risks.",
        "zh": "持续检查安全组规则的合规性，降低安全风险。",
    },
    "rules": [
        "ecs-instance-attached-security-group",
        "ecs-security-group-not-open-all-port",
        "ecs-security-group-not-open-all-protocol",
    ],
}
```

### Policy Validation

The `policy validate` command checks policy files against InfraGuard schema requirements.

#### Rule Validation

- `rule_meta` is required with the following fields:
    - `id` (string) - Required, format: `rule:<provider>:<name>`
    - `name` (string or i18n map) - Required
    - `severity` (string) - Required, must be `high`, `medium`, or `low`
    - `reason` (string or i18n map) - Required
    - `description` (string or i18n map) - Optional
    - `recommendation` (string or i18n map) - Optional
    - `resource_types` (array) - Optional
- `deny` rule is required with result containing:
    - `id` - Rule ID
    - `resource_id` - Resource name from template
    - `violation_path` - Property path array
    - `meta` - Object with `severity` and `reason`

#### Pack Validation

- `pack_meta` is required with the following fields:
    - `id` (string) - Required, format: `pack:<provider>:<name>`
    - `name` (string or i18n map) - Required
    - `rules` (array) - Required, list of short rule IDs
    - `description` (string or i18n map) - Optional

#### I18n String Format

Text fields (`name`, `description`, `reason`, `recommendation`) can be either:

- Simple string: `"My Rule Name"`
- I18n map: `{"en": "English Name", "zh": "中文名称"}`

### Error Handling

- Return localized error messages via i18n system
- Exit codes: 0 (success), 1 (violations found), 2 (high severity violations)
- Provide actionable hints for common errors

### Policy Loading Priority

1. Workspace-local: `.infraguard/policies/` (highest priority, relative to current working directory)
2. User-local: `~/.infraguard/policies/`
3. Embedded: Compiled into binary (fallback)

Policies with the same ID from higher-priority sources override lower-priority ones.

## Development

### Build

```bash
make build          # Build binary
make build-debug    # Build with debug symbols
make install        # Install to GOPATH/bin
```

### Test

```bash
make test           # Run all tests
make test-coverage  # Run tests with coverage report
make test-web       # Run GoConvey web UI
```

### Code Quality

```bash
make format         # Format code
make lint           # Run go vet
make tidy           # Tidy go modules
```

## Dependencies

### Direct Dependencies

- `github.com/spf13/cobra` - CLI framework
- `github.com/open-policy-agent/opa` - Policy evaluation engine
- `github.com/hashicorp/go-getter` - Policy download
- `gopkg.in/yaml.v3` - YAML parsing
- `github.com/fatih/color` - Colored terminal output
- `github.com/olekukonko/tablewriter` - Table rendering
- `github.com/Xuanwo/go-locale` - Locale detection
- `github.com/smartystreets/goconvey` - Testing framework

### Cloud Integration

- Aliyun CLI credentials from `~/.aliyun/config.json`

## File Patterns

| Pattern             | Purpose                |
|---------------------|------------------------|
| `*.rego`            | Rego policy files      |
| `*_test.go`         | Go test files          |
| `*.yaml` / `*.json` | IaC templates          |
| `locales/*.yaml`    | i18n translation files |
