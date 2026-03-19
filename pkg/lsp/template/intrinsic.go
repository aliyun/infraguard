package template

// IntrinsicFunction describes a ROS intrinsic function.
type IntrinsicFunction struct {
	Name        string
	ShortTag    string // YAML short form, e.g. "!Ref"
	Usage       string
	ParamFormat string
}

// ROSIntrinsicFunctions lists all ROS intrinsic functions.
var ROSIntrinsicFunctions = []IntrinsicFunction{
	{Name: "Ref", ShortTag: "!Ref", Usage: "Returns the value of the specified parameter or resource ID", ParamFormat: "!Ref <logicalName>"},
	{Name: "Fn::GetAtt", ShortTag: "!GetAtt", Usage: "Returns the value of an attribute from a resource", ParamFormat: "!GetAtt [resourceName, attributeName]"},
	{Name: "Fn::Join", ShortTag: "!Join", Usage: "Appends a set of values into a single value with a delimiter", ParamFormat: "!Join [delimiter, [value1, value2, ...]]"},
	{Name: "Fn::Sub", ShortTag: "!Sub", Usage: "Substitutes variables in an input string with values", ParamFormat: "!Sub 'string with ${variable}'"},
	{Name: "Fn::Select", ShortTag: "!Select", Usage: "Returns a single object from a list of objects by index", ParamFormat: "!Select [index, [value1, value2, ...]]"},
	{Name: "Fn::Split", ShortTag: "!Split", Usage: "Splits a string into a list of string values", ParamFormat: "!Split [delimiter, sourceString]"},
	{Name: "Fn::Base64Encode", ShortTag: "!Base64Encode", Usage: "Returns the Base64 encoded value of the input string", ParamFormat: "!Base64Encode string"},
	{Name: "Fn::Base64Decode", ShortTag: "!Base64Decode", Usage: "Returns the decoded value of a Base64 encoded string", ParamFormat: "!Base64Decode base64String"},
	{Name: "Fn::FindInMap", ShortTag: "!FindInMap", Usage: "Returns the value corresponding to keys in a two-level map", ParamFormat: "!FindInMap [mapName, firstKey, secondKey]"},
	{Name: "Fn::If", ShortTag: "!If", Usage: "Returns one of two values based on a condition", ParamFormat: "!If [conditionName, trueValue, falseValue]"},
	{Name: "Fn::Equals", ShortTag: "!Equals", Usage: "Compares two values and returns true if they are equal", ParamFormat: "!Equals [value1, value2]"},
	{Name: "Fn::And", ShortTag: "!And", Usage: "Returns true if all conditions are true", ParamFormat: "!And [condition1, condition2, ...]"},
	{Name: "Fn::Or", ShortTag: "!Or", Usage: "Returns true if any condition is true", ParamFormat: "!Or [condition1, condition2, ...]"},
	{Name: "Fn::Not", ShortTag: "!Not", Usage: "Returns true if the condition is false", ParamFormat: "!Not [condition]"},
	{Name: "Fn::Replace", ShortTag: "!Replace", Usage: "Replaces a substring in a string", ParamFormat: "!Replace [{key: value}, string]"},
	{Name: "Fn::GetAZs", ShortTag: "!GetAZs", Usage: "Returns a list of availability zones for the region", ParamFormat: "!GetAZs regionId"},
	{Name: "Fn::GetJsonValue", ShortTag: "!GetJsonValue", Usage: "Extracts a value from a JSON string", ParamFormat: "!GetJsonValue [key, jsonString]"},
	{Name: "Fn::MergeMapToList", ShortTag: "!MergeMapToList", Usage: "Merges multiple maps into a list of maps", ParamFormat: "!MergeMapToList [{key: [values]}, ...]"},
	{Name: "Fn::ListMerge", ShortTag: "!ListMerge", Usage: "Merges multiple lists into a single list", ParamFormat: "!ListMerge [[list1], [list2], ...]"},
	{Name: "Fn::SelectMapList", ShortTag: "!SelectMapList", Usage: "Selects specific keys from a list of maps", ParamFormat: "!SelectMapList [key, [mapList]]"},
	{Name: "Fn::Add", ShortTag: "!Add", Usage: "Adds numeric values", ParamFormat: "!Add [{\"Ref\": \"param\"}, value]"},
	{Name: "Fn::Avg", ShortTag: "!Avg", Usage: "Calculates the average of numeric values", ParamFormat: "!Avg [ndigits, [value1, value2, ...]]"},
	{Name: "Fn::Max", ShortTag: "!Max", Usage: "Returns the maximum value", ParamFormat: "!Max [value1, value2]"},
	{Name: "Fn::Min", ShortTag: "!Min", Usage: "Returns the minimum value", ParamFormat: "!Min [value1, value2]"},
	{Name: "Fn::Calculate", ShortTag: "!Calculate", Usage: "Evaluates a mathematical expression", ParamFormat: "!Calculate [expression, ndigits, [values]]"},
	{Name: "Fn::Length", ShortTag: "!Length", Usage: "Returns the length of a string, list, or map", ParamFormat: "!Length obj"},
	{Name: "Fn::Contains", ShortTag: "!Contains", Usage: "Checks if a list contains a specific value", ParamFormat: "!Contains [[values], value]"},
	{Name: "Fn::Any", ShortTag: "!Any", Usage: "Returns true if any value in a list matches", ParamFormat: "!Any [[values], value]"},
	{Name: "Fn::EachMemberIn", ShortTag: "!EachMemberIn", Usage: "Checks if each member in one list is in another list", ParamFormat: "!EachMemberIn [[values1], [values2]]"},
	{Name: "Fn::MatchPattern", ShortTag: "!MatchPattern", Usage: "Matches a string against a pattern", ParamFormat: "!MatchPattern [pattern, string]"},
	{Name: "Fn::Str", ShortTag: "!Str", Usage: "Converts a value to string", ParamFormat: "!Str value"},
	{Name: "Fn::Index", ShortTag: "!Index", Usage: "Returns the index of an element in a list", ParamFormat: "!Index [value, list]"},
	{Name: "Fn::Indent", ShortTag: "!Indent", Usage: "Indents a multiline string", ParamFormat: "!Indent [indent, padding, string]"},
	{Name: "Fn::GetStackOutput", ShortTag: "!GetStackOutput", Usage: "Gets the output from another stack", ParamFormat: "!GetStackOutput [stackId, outputKey]"},
	{Name: "Fn::Jq", ShortTag: "!Jq", Usage: "Applies a jq expression to a JSON value", ParamFormat: "!Jq [expression, json]"},
	{Name: "Fn::FormatTime", ShortTag: "!FormatTime", Usage: "Formats a timestamp", ParamFormat: "!FormatTime [format, timestamp]"},
	{Name: "Fn::MarketplaceImage", ShortTag: "!MarketplaceImage", Usage: "Returns the image ID from marketplace", ParamFormat: "!MarketplaceImage imageProductCode"},
}

// ROSPseudoParameters lists all ROS pseudo parameters.
var ROSPseudoParameters = []struct {
	Name        string
	Description string
}{
	{Name: "ALIYUN::StackName", Description: "The name of the stack"},
	{Name: "ALIYUN::StackId", Description: "The ID of the stack"},
	{Name: "ALIYUN::Region", Description: "The region of the stack"},
	{Name: "ALIYUN::AccountId", Description: "The account ID of the stack owner"},
	{Name: "ALIYUN::TenantId", Description: "The tenant ID"},
	{Name: "ALIYUN::ResourceGroupId", Description: "The resource group ID"},
	{Name: "ALIYUN::NoValue", Description: "Represents no value (used with Fn::If)"},
	{Name: "ALIYUN::Index", Description: "The index in a Count loop"},
}

// ROSTopLevelBlocks lists all valid top-level blocks in a ROS template.
var ROSTopLevelBlocks = []struct {
	Name        string
	Description string
}{
	{Name: "ROSTemplateFormatVersion", Description: "The template format version (required, value: 2015-09-01)"},
	{Name: "Description", Description: "A text description of the template"},
	{Name: "Metadata", Description: "Template metadata in JSON/YAML format"},
	{Name: "Parameters", Description: "Input parameters for the template"},
	{Name: "Mappings", Description: "Key-value mappings used with Fn::FindInMap"},
	{Name: "Conditions", Description: "Conditions for conditional resource creation"},
	{Name: "Resources", Description: "The cloud resources to create (required)"},
	{Name: "Outputs", Description: "Output values from the stack"},
	{Name: "Rules", Description: "Validation rules for parameter values"},
	{Name: "Locals", Description: "Local variables"},
	{Name: "Transform", Description: "Macros for template transformation"},
	{Name: "Workspace", Description: "Workspace configuration"},
}

// ROSLocalsProperty describes a local variable attribute in a ROS template.
type ROSLocalsProperty struct {
	Name        string
	Required    bool
	Description string
	ValueType   string
}

// ROSLocalsProperties lists all valid local variable attributes per the ROS documentation.
var ROSLocalsProperties = []ROSLocalsProperty{
	{Name: "Type", Required: false, Description: "The type of the local variable: Macro (default, macro substitution), Eval (value calculation), or a DATASOURCE resource type", ValueType: "String"},
	{Name: "Value", Required: false, Description: "The value of the local variable (required for Macro and Eval types)", ValueType: "any"},
	{Name: "Properties", Required: false, Description: "Properties for datasource resource types", ValueType: "Map"},
}

// ROSLocalsTypeValues lists valid Type values for local variables.
var ROSLocalsTypeValues = []struct {
	Name        string
	Description string
}{
	{Name: "Macro", Description: "Macro substitution (default): directly substitutes the value without computing it"},
	{Name: "Eval", Description: "Value calculation: computes the actual value of the local variable, then substitutes it"},
}

// ROSLocalsPropertyTypes maps local variable property names to their expected value types.
var ROSLocalsPropertyTypes map[string]string

func init() {
	ROSLocalsPropertyTypes = make(map[string]string, len(ROSLocalsProperties))
	for _, p := range ROSLocalsProperties {
		ROSLocalsPropertyTypes[p.Name] = p.ValueType
	}
}

// ROSParameterProperty describes a parameter attribute in a ROS template.
type ROSParameterProperty struct {
	Name        string
	Required    bool
	Description string
	ValueType   string
}

// ROSParameterProperties lists all valid parameter attributes per the ROS documentation.
var ROSParameterProperties = []ROSParameterProperty{
	{Name: "Type", Required: true, Description: "The data type of the parameter (String, Number, CommaDelimitedList, Json, Boolean, ALIYUN::OOS::Parameter::Value, ALIYUN::OOS::SecretParameter::Value)", ValueType: "String"},
	{Name: "Default", Required: false, Description: "The default value used when no value is provided during stack creation", ValueType: "any"},
	{Name: "AllowedValues", Required: false, Description: "A list of allowed values for the parameter", ValueType: "List"},
	{Name: "AllowedPattern", Required: false, Description: "A regular expression to validate String type parameter values", ValueType: "String"},
	{Name: "MaxLength", Required: false, Description: "The maximum length of a String type parameter value", ValueType: "Integer"},
	{Name: "MinLength", Required: false, Description: "The minimum length of a String type parameter value", ValueType: "Integer"},
	{Name: "MaxValue", Required: false, Description: "The maximum numeric value for a Number type parameter", ValueType: "Number"},
	{Name: "MinValue", Required: false, Description: "The minimum numeric value for a Number type parameter", ValueType: "Number"},
	{Name: "NoEcho", Required: false, Description: "If true, the parameter value is masked with asterisks (*)", ValueType: "Boolean"},
	{Name: "Confirm", Required: false, Description: "If true, requires a second input confirmation when NoEcho is true", ValueType: "Boolean"},
	{Name: "Description", Required: false, Description: "A description of the parameter, supports zh-cn and en keys", ValueType: "String/Map"},
	{Name: "ConstraintDescription", Required: false, Description: "A message explaining the constraint when validation fails, supports zh-cn and en keys", ValueType: "String/Map"},
	{Name: "Label", Required: false, Description: "An alias for the parameter, mapped to a label in web forms", ValueType: "String/Map"},
	{Name: "AssociationProperty", Required: false, Description: "Automatically validates parameter values and provides selectable options", ValueType: "String"},
	{Name: "AssociationPropertyMetadata", Required: false, Description: "Defines constraints for AssociationProperty filtering", ValueType: "Map"},
	{Name: "TextArea", Required: false, Description: "Whether the parameter supports line breaks (true/false)", ValueType: "Boolean"},
	{Name: "Required", Required: false, Description: "Whether the parameter is required (true/false), UI-only effect", ValueType: "Boolean"},
	{Name: "Placeholder", Required: false, Description: "Custom placeholder text for the input field, supports en and zh-cn keys", ValueType: "Map"},
}

// ROSParameterTypeValues lists all valid Type values for parameters.
var ROSParameterTypeValues = []struct {
	Name        string
	Description string
}{
	{Name: "String", Description: "A string value, e.g. \"ecs.s1.medium\""},
	{Name: "Number", Description: "An integer or float value, e.g. 3.14"},
	{Name: "CommaDelimitedList", Description: "A comma-delimited list of values, e.g. \"80,foo,bar\""},
	{Name: "Json", Description: "A JSON-formatted string, e.g. {\"foo\": \"bar\"}"},
	{Name: "Boolean", Description: "A boolean value: true or false"},
	{Name: "ALIYUN::OOS::Parameter::Value", Description: "A common parameter stored in OOS Parameter Store"},
	{Name: "ALIYUN::OOS::SecretParameter::Value", Description: "An encrypted parameter stored in OOS Parameter Store"},
}

// ROSParameterPropertyTypes maps parameter property names to their expected value types.
var ROSParameterPropertyTypes map[string]string

// ValidParameterTypeValues is a set of valid Type field values for quick lookup.
var ValidParameterTypeValues map[string]bool

func init() {
	ROSParameterPropertyTypes = make(map[string]string, len(ROSParameterProperties))
	for _, p := range ROSParameterProperties {
		ROSParameterPropertyTypes[p.Name] = p.ValueType
	}

	ValidParameterTypeValues = make(map[string]bool, len(ROSParameterTypeValues))
	for _, t := range ROSParameterTypeValues {
		ValidParameterTypeValues[t.Name] = true
	}
}

// IsParamAttrTypeValid checks whether a value matches the expected type for a parameter property.
func IsParamAttrTypeValid(val interface{}, expectedType string) bool {
	if expectedType == "" || expectedType == "any" {
		return true
	}
	if IsIntrinsicFunctionValue(val) {
		return true
	}
	switch expectedType {
	case "String":
		_, ok := val.(string)
		return ok
	case "Integer":
		switch v := val.(type) {
		case int, int64, uint64:
			return true
		case float64:
			return v == float64(int64(v))
		}
		return false
	case "Number":
		switch val.(type) {
		case int, int64, uint64, float64:
			return true
		}
		return false
	case "Boolean":
		_, ok := val.(bool)
		return ok
	case "List":
		_, ok := val.([]interface{})
		return ok
	case "Map":
		_, ok := val.(map[string]interface{})
		return ok
	case "String/Map":
		_, isString := val.(string)
		_, isMap := val.(map[string]interface{})
		return isString || isMap
	}
	return true
}

// DescribeValueType returns a human-readable type name for a Go value.
func DescribeValueType(val interface{}) string {
	switch val.(type) {
	case string:
		return "String"
	case int, int64, uint64:
		return "Integer"
	case float64:
		return "Number"
	case bool:
		return "Boolean"
	case []interface{}:
		return "List"
	case map[string]interface{}:
		return "Map"
	default:
		return "Unknown"
	}
}

// GetIntrinsicFunction returns the intrinsic function metadata by name.
func GetIntrinsicFunction(name string) *IntrinsicFunction {
	for i := range ROSIntrinsicFunctions {
		f := &ROSIntrinsicFunctions[i]
		if f.Name == name || f.ShortTag == name {
			return f
		}
	}
	return nil
}

// IsIntrinsicFunctionValue checks if a value is an intrinsic function call.
func IsIntrinsicFunctionValue(val interface{}) bool {
	m, ok := val.(map[string]interface{})
	if !ok {
		return false
	}
	for key := range m {
		if key == "Ref" || (len(key) > 4 && key[:4] == "Fn::") {
			return true
		}
	}
	return false
}
