package ros

import (
	"encoding/json"
	"fmt"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/resolver"
	"gopkg.in/yaml.v3"
)

// Mode represents the loading mode
type Mode string

const (
	// ModeStatic uses static analysis
	ModeStatic Mode = "static"
	// ModePreview uses ROS PreviewStack API
	ModePreview Mode = "preview"
)

// Load loads a ROS template using the specified mode
// Returns yaml.Node (for error location mapping) and template data (for policy evaluation)
func Load(mode Mode, templatePath string, inputParams map[string]interface{}) (*yaml.Node, map[string]interface{}, error) {
	msg := i18n.Msg()
	switch mode {
	case ModeStatic:
		return loadStatic(templatePath, inputParams)
	case ModePreview:
		return loadPreview(templatePath, inputParams)
	default:
		return nil, nil, fmt.Errorf(msg.Errors.PreviewUnsupportedMode, mode)
	}
}

// loadStatic loads template using static analysis
func loadStatic(templatePath string, inputParams map[string]interface{}) (*yaml.Node, map[string]interface{}, error) {
	msg := i18n.Msg()

	// Load template
	yamlRoot, templateData, err := LoadLocalTemplate(templatePath)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedLoadTemplate, err)
	}

	// Validate ROS template structure
	if err := ValidateROSTemplate(templateData); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSInvalidTemplate, err)
	}

	// Validate input parameters
	if err := ValidateInputParameters(templateData, inputParams); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSInvalidParameters, err)
	}

	// Resolve parameters
	resolvedTemplate, err := ResolveParameters(templateData, inputParams)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedResolveParameters, err)
	}

	// Resolve conditions and intrinsic functions
	resolvedTemplate = resolver.ResolveConditionsAndFunctions(resolvedTemplate, nil)

	return yamlRoot, resolvedTemplate, nil
}

// loadPreview loads template using ROS PreviewStack API
func loadPreview(templatePath string, inputParams map[string]interface{}) (*yaml.Node, map[string]interface{}, error) {
	msg := i18n.Msg()

	// Step 1: Load template file content
	yamlRoot, templateData, err := LoadLocalTemplate(templatePath)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedLoadTemplate, err)
	}

	// Validate ROS template structure
	if err := ValidateROSTemplate(templateData); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSInvalidTemplate, err)
	}

	// Validate input parameters
	if err := ValidateInputParameters(templateData, inputParams); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSInvalidParameters, err)
	}

	// Step 2: Load credentials
	cred, err := LoadCredentials()
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedLoadCredentials, err)
	}

	// Validate credentials
	if err := cred.Validate(); err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSInvalidCredentials, err)
	}

	// Step 3: Create ROS client
	client, err := NewClient(cred)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedCreateClient, err)
	}

	// Step 4: Convert template to JSON string for API call
	templateJSON, err := json.Marshal(templateData)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedMarshalTemplate, err)
	}

	// Step 5: Call PreviewStack API
	request := &PreviewStackRequest{
		TemplateBody: string(templateJSON),
		Parameters:   inputParams,
		Region:       cred.Region,
	}

	previewResponse, err := CallPreviewStack(client, request)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedCallAPI, err)
	}

	// Step 6: Convert preview response to template format
	convertedTemplate, err := ConvertPreviewToTemplate(previewResponse)
	if err != nil {
		return nil, nil, fmt.Errorf(msg.Errors.ROSFailedConvertResponse, err)
	}

	// Return yamlRoot from original file for error location mapping
	// and converted template data for policy evaluation
	return yamlRoot, convertedTemplate, nil
}
