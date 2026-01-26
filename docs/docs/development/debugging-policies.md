---
title: Debugging Policies
---

# Debugging Rego Policies

There are two ways to debug your Rego policies: using print statements or using VSCode debugger.

## Method 1: Using Print Statements

### Basic Usage

Add `print()` statements anywhere in your Rego policy:

```rego
package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

deny contains result if {
    print("Starting policy evaluation")
    
    some name, resource in helpers.resources_by_types(rule_meta.resource_types)
    print("Checking resource:", name)
    print("Resource type:", resource.Type)
    
    not is_compliant(resource)
    print("Found violation for resource:", name)
    
    result := {...}
}
```

### Output Format

Print statements output to stderr with file location:

```
/path/to/policy.rego:42: Starting policy evaluation
/path/to/policy.rego:45: Checking resource: MyBucket
/path/to/policy.rego:46: Resource type: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: Found violation for resource: MyBucket
```

### Common Usage Examples

**Inspecting Input Data:**
```rego
print("Input keys:", object.keys(input))
print("Template version:", input.ROSTemplateFormatVersion)
print("Number of resources:", count(input.Resources))
```

**Debugging Resource Iteration:**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("Resource:", name)
print("Properties:", object.keys(resource.Properties))
```

**Checking Conditions:**
```rego
condition1 := some_check(resource)
print("Condition 1 result:", condition1)
```

**Inspecting Variables:**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("Property value:", property)
print("Property type:", type_name(property))
```

## Method 2: Using VSCode Debugger

VSCode provides a more powerful debugging experience with breakpoints, variable inspection, and step-by-step execution.

### Prerequisites

1. **Install OPA**

   Download and install OPA from the official website:
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **Install Regal**

   Install Regal for enhanced Rego development:
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **Install VSCode OPA Extension**

   Install the official OPA extension from the VSCode marketplace:
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### Setup Steps

1. **Prepare Test Input**

   Create a file named `input.json` in your policy directory with your test data:

   ```json
   {
     "ROSTemplateFormatVersion": "2015-09-01",
     "Resources": {
       "MyBucket": {
         "Type": "ALIYUN::OSS::Bucket",
         "Properties": {
           "BucketName": "test-bucket",
           "AccessControl": "private"
         }
       }
     }
   }
   ```

2. **Set Breakpoints**

   Open your `.rego` policy file in VSCode and click on the left margin to set breakpoints where you want to pause execution.

3. **Start Debugging**

   - Press `F5` or go to Run → Start Debugging
   - The debugger will pause at your breakpoints
   - You can inspect variables, step through code, and evaluate expressions

## Choosing a Method

- **Print Statements**: Quick and simple, works in any environment, useful for production debugging
- **VSCode Debugger**: More powerful, interactive debugging with full variable inspection, better for development

You can use both methods together: use print statements for quick checks and the debugger for deep investigation.
