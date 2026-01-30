---
title: ROS Features Support
---

# ROS Features Support

InfraGuard supports a wide range of ROS (Resource Orchestration Service) template features for static analysis and validation of your infrastructure code.

## Functions

InfraGuard supports the following ROS functions:

### String Functions
- [`Fn::Join`](https://www.alibabacloud.com/help/en/ros/user-guide/function-join) - Joins strings with a delimiter
- [`Fn::Sub`](https://www.alibabacloud.com/help/en/ros/user-guide/function-sub) - Substitutes variables in a string
- [`Fn::Split`](https://www.alibabacloud.com/help/en/ros/user-guide/function-split) - Splits a string into a list
- [`Fn::Replace`](https://www.alibabacloud.com/help/en/ros/user-guide/function-replace) - Replaces strings in text
- [`Fn::Str`](https://www.alibabacloud.com/help/en/ros/user-guide/function-str) - Converts values to strings
- [`Fn::Indent`](https://www.alibabacloud.com/help/en/ros/user-guide/function-indent) - Indents text

### Encoding Functions
- [`Fn::Base64Encode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64encode) - Encodes to Base64
- [`Fn::Base64Decode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64decode) - Decodes from Base64

### List Functions
- [`Fn::Select`](https://www.alibabacloud.com/help/en/ros/user-guide/function-select) - Selects an element from a list
- [`Fn::Index`](https://www.alibabacloud.com/help/en/ros/user-guide/function-index) - Finds the index of an element
- [`Fn::Length`](https://www.alibabacloud.com/help/en/ros/user-guide/function-length) - Returns the length of a list or string
- [`Fn::ListMerge`](https://www.alibabacloud.com/help/en/ros/user-guide/function-listmerge) - Merges multiple lists

### Map Functions
- [`Fn::FindInMap`](https://www.alibabacloud.com/help/en/ros/user-guide/function-findinmap) - Retrieves values from a mapping
- [`Fn::SelectMapList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-selectmaplist) - Selects values from a list of maps
- [`Fn::MergeMapToList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-mergemaptolist) - Merges maps into a list

### Mathematical Functions
- [`Fn::Add`](https://www.alibabacloud.com/help/en/ros/user-guide/function-add) - Adds numbers
- [`Fn::Avg`](https://www.alibabacloud.com/help/en/ros/user-guide/function-avg) - Calculates average
- [`Fn::Max`](https://www.alibabacloud.com/help/en/ros/user-guide/function-max) - Returns maximum value
- [`Fn::Min`](https://www.alibabacloud.com/help/en/ros/user-guide/function-min) - Returns minimum value
- [`Fn::Calculate`](https://www.alibabacloud.com/help/en/ros/user-guide/function-calculate) - Evaluates mathematical expressions

### Conditional Functions
- [`Fn::If`](https://www.alibabacloud.com/help/en/ros/user-guide/function-if) - Returns values based on conditions
- [`Fn::Equals`](https://www.alibabacloud.com/help/en/ros/user-guide/function-equals) - Compares two values
- [`Fn::And`](https://www.alibabacloud.com/help/en/ros/user-guide/function-and) - Logical AND
- [`Fn::Or`](https://www.alibabacloud.com/help/en/ros/user-guide/function-or) - Logical OR
- [`Fn::Not`](https://www.alibabacloud.com/help/en/ros/user-guide/function-not) - Logical NOT
- [`Fn::Contains`](https://www.alibabacloud.com/help/en/ros/user-guide/function-contains) - Checks if a value is in a list
- [`Fn::Any`](https://www.alibabacloud.com/help/en/ros/user-guide/function-any) - Checks if any condition is true
- [`Fn::EachMemberIn`](https://www.alibabacloud.com/help/en/ros/user-guide/function-eachmemberin) - Checks if all elements are in another list
- [`Fn::MatchPattern`](https://www.alibabacloud.com/help/en/ros/user-guide/function-matchpattern) - Matches against a pattern

### Utility Functions
- [`Fn::GetJsonValue`](https://www.alibabacloud.com/help/en/ros/user-guide/function-getjsonvalue) - Extracts values from JSON
- [`Ref`](https://www.alibabacloud.com/help/en/ros/user-guide/ref) - References parameters and resources

## Conditions

InfraGuard fully supports the [ROS Conditions](https://www.alibabacloud.com/help/ros/user-guide/conditions) feature, including:

- **Condition Definition** - Define conditions in the `Conditions` section
- **Condition Functions** - Use `Fn::Equals`, `Fn::And`, `Fn::Or`, `Fn::Not`, `Fn::If` in conditions
- **Condition References** - Reference conditions in resources and outputs
- **Dependency Resolution** - Automatically resolves condition dependencies

## YAML Short Syntax

InfraGuard supports the YAML short syntax (tag notation) for ROS functions:

- `!Ref` - Short form of `Ref`
- `!GetAtt` - Short form of `Fn::GetAtt`
- All other `Fn::*` functions can be written as `!FunctionName`

The YAML parser automatically converts these short forms to their standard map representation during template loading.

## Unsupported Features

InfraGuard focuses on static analysis and currently does not support the following features:

### Runtime Functions
- `Fn::GetAtt` - Requires actual resource creation to retrieve attributes
- `Fn::GetAZs` - Requires runtime query to cloud provider
- `Fn::GetStackOutput` - Requires access to other stack outputs

### Template Sections
- `Locals` - Local variable definitions
- `Transform` - Template transformations and macros
- `Rules` - Template validation rules
- `Mappings` - Static value mappings (not analyzed for policy violations)

### Special References
- Pseudo parameters (e.g., `ALIYUN::StackId`, `ALIYUN::Region`, etc.) - System-provided parameters

These features will be preserved as-is in the analysis output without evaluation or validation.

## Related Resources

- [ROS Template Structure](https://www.alibabacloud.com/help/en/ros/user-guide/template-structure)
- [ROS Functions](https://www.alibabacloud.com/help/en/ros/user-guide/functions)
- [ROS Conditions](https://www.alibabacloud.com/help/en/ros/user-guide/conditions)
