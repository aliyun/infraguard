// Package loader handles template loading and parsing.
package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"gopkg.in/yaml.v3"
)

// ValidROSTemplateFormatVersions contains all valid ROS template format versions.
var ValidROSTemplateFormatVersions = []string{
	"2015-09-01",
}

// ROSTemplateValidationError represents a ROS template validation error.
type ROSTemplateValidationError struct {
	Field   string
	Message string
}

func (e *ROSTemplateValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateROSTemplate validates that the given data is a valid ROS template.
// It checks for required fields: ROSTemplateFormatVersion and Resources.
func ValidateROSTemplate(data map[string]interface{}) error {
	// Check ROSTemplateFormatVersion
	version, ok := data["ROSTemplateFormatVersion"]
	if !ok {
		return &ROSTemplateValidationError{
			Field:   "ROSTemplateFormatVersion",
			Message: "missing required field.",
		}
	}

	// Validate version format
	versionStr, ok := version.(string)
	if !ok {
		return &ROSTemplateValidationError{
			Field:   "ROSTemplateFormatVersion",
			Message: "must be a string.",
		}
	}

	// Check if version is valid
	validVersion := false
	for _, v := range ValidROSTemplateFormatVersions {
		if versionStr == v {
			validVersion = true
			break
		}
	}
	if !validVersion {
		msg := i18n.Msg()
		return &ROSTemplateValidationError{
			Field:   "ROSTemplateFormatVersion",
			Message: fmt.Sprintf(msg.Errors.InvalidROSTemplateVersion, versionStr, ValidROSTemplateFormatVersions),
		}
	}

	// Check Resources
	resources, ok := data["Resources"]
	if !ok {
		return &ROSTemplateValidationError{
			Field:   "Resources",
			Message: "missing required field.",
		}
	}

	// Resources should be a map
	resourcesMap, ok := resources.(map[string]interface{})
	if !ok {
		return &ROSTemplateValidationError{
			Field:   "Resources",
			Message: "must be a map.",
		}
	}

	// Validate each resource
	for resourceName, resource := range resourcesMap {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			return &ROSTemplateValidationError{
				Field:   fmt.Sprintf("Resources.%s", resourceName),
				Message: "must be a map.",
			}
		}

		// Each resource must have Type (string)
		resourceType, hasType := resourceMap["Type"]
		if !hasType {
			return &ROSTemplateValidationError{
				Field:   fmt.Sprintf("Resources.%s.Type", resourceName),
				Message: "missing required field.",
			}
		}
		if _, ok := resourceType.(string); !ok {
			return &ROSTemplateValidationError{
				Field:   fmt.Sprintf("Resources.%s.Type", resourceName),
				Message: "must be a string.",
			}
		}

		// If Properties exists, it must be a map
		if properties, hasProps := resourceMap["Properties"]; hasProps {
			if _, ok := properties.(map[string]interface{}); !ok {
				return &ROSTemplateValidationError{
					Field:   fmt.Sprintf("Resources.%s.Properties", resourceName),
					Message: "must be a map.",
				}
			}
		}
	}

	return nil
}

// convertYAMLNode recursively converts a yaml.Node to a generic interface{},
// handling ROS intrinsic function tags (!Ref, !Join, etc.) by converting them
// to their standard map representation.
func convertYAMLNode(node *yaml.Node) (interface{}, error) {
	// Handle tagged nodes (!Ref, !Join, etc.)
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		tag := node.Tag

		// Remove the ! prefix (if present)
		tag = strings.TrimPrefix(tag, "!")

		// Decode the value recursively based on node kind
		var value interface{}
		var err error

		switch node.Kind {
		case yaml.ScalarNode:
			// For scalar nodes, just decode the value
			err = node.Decode(&value)
		case yaml.SequenceNode:
			// For sequence nodes, convert each element
			arr := make([]interface{}, len(node.Content))
			for i, child := range node.Content {
				arr[i], err = convertYAMLNode(child)
				if err != nil {
					return nil, err
				}
			}
			value = arr
		case yaml.MappingNode:
			// For mapping nodes, convert to map
			value, err = convertMappingNode(node)
		default:
			err = node.Decode(&value)
		}

		if err != nil {
			return nil, err
		}

		// Convert to map format
		if tag == "Ref" {
			return map[string]interface{}{"Ref": value}, nil
		}
		// All other tags become Fn::TagName
		return map[string]interface{}{"Fn::" + tag: value}, nil
	}

	// Handle standard nodes
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) > 0 {
			return convertYAMLNode(node.Content[0])
		}
		return nil, nil

	case yaml.MappingNode:
		return convertMappingNode(node)

	case yaml.SequenceNode:
		s := make([]interface{}, len(node.Content))
		for i, child := range node.Content {
			value, err := convertYAMLNode(child)
			if err != nil {
				return nil, err
			}
			s[i] = value
		}
		return s, nil

	default:
		// Scalar values
		var value interface{}
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		return value, nil
	}
}

// convertMappingNode converts a YAML mapping node to a map
func convertMappingNode(node *yaml.Node) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	for i := 0; i < len(node.Content)-1; i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var key string
		if err := keyNode.Decode(&key); err != nil {
			return nil, err
		}

		value, err := convertYAMLNode(valueNode)
		if err != nil {
			return nil, err
		}
		m[key] = value
	}
	return m, nil
}

// LoadLocal loads a template file (YAML or JSON) and returns:
// - yamlRoot: the yaml.Node AST for source mapping (nil for JSON files)
// - data: the parsed template as a map for OPA evaluation
func LoadLocal(path string) (*yaml.Node, map[string]interface{}, error) {
	msg := i18n.Msg()
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ReadTemplateFile, err)
	}

	// Try to detect format
	isJSON := strings.HasSuffix(strings.ToLower(path), ".json") ||
		(len(content) > 0 && (content[0] == '{' || content[0] == '['))

	if isJSON {
		// JSON file - parse directly
		var data map[string]interface{}
		if err := json.Unmarshal(content, &data); err != nil {
			return nil, nil, fmt.Errorf(msg.Errors.ParseJSONTemplate, err)
		}
		// For JSON, we still try to create a YAML node for potential source mapping
		var node yaml.Node
		if err := yaml.Unmarshal(content, &node); err != nil {
			// JSON might not parse as YAML in some edge cases, that's ok
			return nil, data, nil
		}
		return &node, data, nil
	}

	// YAML file - parse with AST preservation
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ParseYAMLTemplate, err)
	}

	// Convert YAML with custom tag handling
	data, err := convertYAMLNode(&node)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ParseYAMLTemplate, err)
	}

	// Handle empty files or non-map root
	if data == nil {
		return &node, make(map[string]interface{}), nil
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf(msg.Errors.ParseYAMLTemplate, fmt.Errorf("expected map at root"))
	}

	return &node, dataMap, nil
}
