package ros

import (
	"encoding/json"
	"fmt"
	"time"

	ros "github.com/alibabacloud-go/ros-20190910/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/infraguard/pkg/i18n"
)

// PreviewStackRequest represents the request parameters for PreviewStack API
type PreviewStackRequest struct {
	StackName    string
	TemplateBody string
	Parameters   map[string]interface{}
	Region       string
}

// PreviewStackResponse represents the parsed response from PreviewStack API
type PreviewStackResponse struct {
	Stack *StackInfo
}

// StackInfo contains the stack information from preview
type StackInfo struct {
	Resources []*ResourceInfo
}

// ResourceInfo represents a resource in the stack
type ResourceInfo struct {
	LogicalResourceId string
	ResourceType      string
	Properties        map[string]interface{}
	DependsOn         []string
}

// CallPreviewStack calls the ROS PreviewStack API
func CallPreviewStack(client *ros.Client, request *PreviewStackRequest) (*PreviewStackResponse, error) {
	msg := i18n.Msg()
	if client == nil {
		return nil, fmt.Errorf("%s", msg.Errors.ROSClientNil)
	}

	// Generate a unique stack name if not provided
	stackName := request.StackName
	if stackName == "" {
		stackName = fmt.Sprintf("infraguard-preview-%d", time.Now().Unix())
	}

	// Convert parameters to ROS API format
	var parameters []*ros.PreviewStackRequestParameters
	for key, value := range request.Parameters {
		param := &ros.PreviewStackRequestParameters{
			ParameterKey: tea.String(key),
		}

		// Convert value to string
		switch v := value.(type) {
		case string:
			param.ParameterValue = tea.String(v)
		case int, int64, float64, bool:
			param.ParameterValue = tea.String(fmt.Sprintf("%v", v))
		default:
			// For complex types, marshal to JSON
			msg := i18n.Msg()
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf(msg.Errors.ROSFailedMarshalParameter, key, err)
			}
			param.ParameterValue = tea.String(string(jsonBytes))
		}

		parameters = append(parameters, param)
	}

	// Construct PreviewStack request
	apiRequest := &ros.PreviewStackRequest{
		RegionId:     tea.String(request.Region),
		StackName:    tea.String(stackName),
		TemplateBody: tea.String(request.TemplateBody),
	}

	if len(parameters) > 0 {
		apiRequest.Parameters = parameters
	}

	// Output API call information
	fmt.Printf("%s\n", fmt.Sprintf(msg.Scan.CallingPreviewStack, request.Region))

	// Call PreviewStack API
	response, err := client.PreviewStack(apiRequest)
	if err != nil {
		return nil, handleAPIError(err)
	}

	// Parse response
	return parsePreviewStackResponse(response)
}

// FormattedAPIError represents a formatted API error with structured information
type FormattedAPIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *FormattedAPIError) Error() string {
	// Format error message without redundant Data field
	msg := fmt.Sprintf("StatusCode: %d\nCode: %s\nMessage: %s", e.StatusCode, e.Code, e.Message)
	if e.RequestID != "" {
		msg += fmt.Sprintf("\nRequestId: %s", e.RequestID)
	}
	return msg
}

// handleAPIError processes API errors and returns user-friendly messages
func handleAPIError(err error) error {
	if err == nil {
		return nil
	}

	msg := i18n.Msg()
	errMsg := err.Error()

	// Try to parse SDKError structure
	if sdkErr, ok := err.(*tea.SDKError); ok {
		formattedErr := &FormattedAPIError{
			StatusCode: tea.IntValue(sdkErr.StatusCode),
			Code:       tea.StringValue(sdkErr.Code),
			Message:    tea.StringValue(sdkErr.Message),
		}

		// Extract RequestId from Data if available
		// Data is a JSON string, so we need to parse it
		if sdkErr.Data != nil {
			dataStr := tea.StringValue(sdkErr.Data)
			if dataStr != "" {
				var dataMap map[string]interface{}
				if err := json.Unmarshal([]byte(dataStr), &dataMap); err == nil {
					if requestID, ok := dataMap["RequestId"].(string); ok {
						formattedErr.RequestID = requestID
					}
				}
			}
		}

		// Check for common error types and return user-friendly messages
		code := formattedErr.Code
		switch {
		case contains(code, "InvalidAccessKeyId"):
			return fmt.Errorf("%s", msg.Errors.ROSAuthInvalidAccessKey)
		case contains(code, "SignatureDoesNotMatch"):
			return fmt.Errorf("%s", msg.Errors.ROSAuthSignatureMismatch)
		case contains(code, "Forbidden.RAM"):
			return fmt.Errorf("%s", msg.Errors.ROSAuthInsufficientPermissions)
		case contains(code, "Throttling"):
			return fmt.Errorf("%s", msg.Errors.ROSRateLimit)
		case contains(code, "ServiceUnavailable"):
			return fmt.Errorf("%s", msg.Errors.ROSServiceUnavailable)
		case contains(code, "TemplateValidationError"), contains(code, "StackValidationFailed"):
			return formattedErr
		case contains(errMsg, "NetworkError"), contains(errMsg, "timeout"):
			return fmt.Errorf("%s", msg.Errors.ROSNetworkError)
		default:
			return formattedErr
		}
	}

	// Fallback to string-based error checking for non-SDKError types
	switch {
	case contains(errMsg, "InvalidAccessKeyId"):
		return fmt.Errorf("%s", msg.Errors.ROSAuthInvalidAccessKey)
	case contains(errMsg, "SignatureDoesNotMatch"):
		return fmt.Errorf("%s", msg.Errors.ROSAuthSignatureMismatch)
	case contains(errMsg, "Forbidden.RAM"):
		return fmt.Errorf("%s", msg.Errors.ROSAuthInsufficientPermissions)
	case contains(errMsg, "Throttling"):
		return fmt.Errorf("%s", msg.Errors.ROSRateLimit)
	case contains(errMsg, "ServiceUnavailable"):
		return fmt.Errorf("%s", msg.Errors.ROSServiceUnavailable)
	case contains(errMsg, "TemplateValidationError"), contains(errMsg, "StackValidationFailed"):
		return fmt.Errorf(msg.Errors.ROSTemplateValidationFailed, err)
	case contains(errMsg, "NetworkError"), contains(errMsg, "timeout"):
		return fmt.Errorf("%s", msg.Errors.ROSNetworkError)
	default:
		return fmt.Errorf(msg.Errors.ROSAPIError, err)
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// parsePreviewStackResponse parses the ROS API response
func parsePreviewStackResponse(response *ros.PreviewStackResponse) (*PreviewStackResponse, error) {
	msg := i18n.Msg()
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("%s", msg.Errors.ROSEmptyResponse)
	}

	body := response.Body

	// Check if Stack exists in response
	if body.Stack == nil {
		return nil, fmt.Errorf("%s", msg.Errors.ROSNoStackInfo)
	}

	// Parse resources
	var resources []*ResourceInfo
	if body.Stack.Resources != nil {
		for _, res := range body.Stack.Resources {
			if res == nil {
				continue
			}

			resourceInfo := &ResourceInfo{
				LogicalResourceId: tea.StringValue(res.LogicalResourceId),
				ResourceType:      tea.StringValue(res.ResourceType),
			}

			// Properties is already a map[string]interface{} in the SDK
			if res.Properties != nil {
				resourceInfo.Properties = res.Properties
			}

			// Convert RequiredBy to DependsOn (reverse dependency)
			// Note: RequiredBy indicates which resources depend on this resource
			// We'll store it as-is for now, as it provides dependency information
			if res.RequiredBy != nil && len(res.RequiredBy) > 0 {
				for _, dep := range res.RequiredBy {
					if dep != nil {
						resourceInfo.DependsOn = append(resourceInfo.DependsOn, *dep)
					}
				}
			}

			resources = append(resources, resourceInfo)
		}
	}

	return &PreviewStackResponse{
		Stack: &StackInfo{
			Resources: resources,
		},
	}, nil
}

// ConvertPreviewToTemplate converts PreviewStack response to ROS template format
// This ensures the data structure matches what static analysis produces
func ConvertPreviewToTemplate(response *PreviewStackResponse) (map[string]interface{}, error) {
	msg := i18n.Msg()
	if response == nil || response.Stack == nil {
		return nil, fmt.Errorf("%s", msg.Errors.ROSInvalidPreviewResponse)
	}

	// Build the template structure
	template := map[string]interface{}{
		"ROSTemplateFormatVersion": "2015-09-01",
		"Resources":                make(map[string]interface{}),
	}

	resources := template["Resources"].(map[string]interface{})

	// Convert each resource
	for _, res := range response.Stack.Resources {
		if res == nil || res.LogicalResourceId == "" {
			continue
		}

		resource := map[string]interface{}{
			"Type": res.ResourceType,
		}

		// Add Properties if present
		if res.Properties != nil && len(res.Properties) > 0 {
			resource["Properties"] = res.Properties
		}

		// Add DependsOn if present
		if len(res.DependsOn) > 0 {
			resource["DependsOn"] = res.DependsOn
		}

		resources[res.LogicalResourceId] = resource
	}

	return template, nil
}
