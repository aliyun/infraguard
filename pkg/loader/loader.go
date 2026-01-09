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

	// Also parse as generic map for OPA
	var data map[string]interface{}
	if err := yaml.Unmarshal(content, &data); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ParseYAMLTemplate, err)
	}

	return &node, data, nil
}
