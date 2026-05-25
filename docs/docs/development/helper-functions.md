---
title: Helper Functions
---

# Helper Functions

InfraGuard provides helper functions to simplify policy writing.

For ROS rules, import them with:
```rego
import data.infraguard.helpers
```

For Terraform rules, import the Terraform helper module:

```rego
import data.infraguard.helpers.terraform as tf
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

## Terraform Functions

| Function | Description |
|----------|-------------|
| `tf.resources_by_type(type)` | Get Terraform resources of a type as `{name: resource}` map |
| `tf.has_resource_type(type)` | Check if a Terraform resource type exists |
| `tf.get_attribute(resource, attr, default)` | Get an evaluated Terraform attribute with default value |
| `tf.is_unknown(value)` | Check if an attribute could not be resolved statically |

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
