---
title: Helper Functions
---

# Helper Functions

InfraGuard provides helper functions to simplify policy writing.

Import them with:
```rego
import data.infraguard.helpers
```

## Available Functions

| Function | Description |
|----------|-------------|
| `resources_by_type(type)` | Get all resources of a type as `{name: resource}` map |
| `resource_names_by_type(type)` | Get all resource names of a type as list |
| `count_resources_by_type(type)` | Count resources of a type |
| `resource_exists(type)` | Check if resource type exists |
| `has_property(resource, prop)` | Check if property exists and is not null |
| `get_property(resource, prop, default)` | Get property with default value |
| `is_true(v)` / `is_false(v)` | Check boolean (handles string "true"/"false") |
| `is_public_cidr(cidr)` | Check if CIDR is `0.0.0.0/0` or `::/0` |
| `includes(list, elem)` | Check if element is in list |

## Examples

```rego
# Get all ECS instances
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Check logic here
}

# Check if property exists
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # Violation logic
}

# Check for public CIDR
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # Violation logic
}
```

For more examples, see [Writing Rules](./writing-rules).

