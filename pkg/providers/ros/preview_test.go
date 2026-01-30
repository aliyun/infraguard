package ros

import (
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
)

func TestHandleAPIError(t *testing.T) {
	// Set language to English for consistent test results
	oldLang := i18n.GetLanguage()
	i18n.SetLanguage("en")
	defer i18n.SetLanguage(oldLang)

	tests := []struct {
		name        string
		err         error
		wantContain string
	}{
		{
			name:        "nil error",
			err:         nil,
			wantContain: "",
		},
		{
			name:        "invalid access key",
			err:         &mockError{msg: "InvalidAccessKeyId.NotFound"},
			wantContain: "invalid access key ID",
		},
		{
			name:        "signature mismatch",
			err:         &mockError{msg: "SignatureDoesNotMatch"},
			wantContain: "signature does not match",
		},
		{
			name:        "forbidden ram",
			err:         &mockError{msg: "Forbidden.RAM"},
			wantContain: "insufficient permissions",
		},
		{
			name:        "throttling",
			err:         &mockError{msg: "Throttling.User"},
			wantContain: "rate limit exceeded",
		},
		{
			name:        "service unavailable",
			err:         &mockError{msg: "ServiceUnavailable"},
			wantContain: "temporarily unavailable",
		},
		{
			name:        "template validation",
			err:         &mockError{msg: "TemplateValidationError: missing required field"},
			wantContain: "template validation failed",
		},
		{
			name:        "network error",
			err:         &mockError{msg: "NetworkError: connection timeout"},
			wantContain: "network error",
		},
		{
			name:        "generic error",
			err:         &mockError{msg: "Unknown error occurred"},
			wantContain: "ROS API error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleAPIError(tt.err)

			if tt.wantContain == "" {
				if err != nil {
					t.Errorf("handleAPIError() = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatal("handleAPIError() = nil, want error")
			}

			if !containsSubstring(err.Error(), tt.wantContain) {
				t.Errorf("handleAPIError() error = %v, want to contain %q", err, tt.wantContain)
			}
		})
	}
}

func TestConvertPreviewToTemplate(t *testing.T) {
	tests := []struct {
		name    string
		input   *PreviewStackResponse
		wantErr bool
		check   func(*testing.T, map[string]interface{})
	}{
		{
			name: "valid response with single resource",
			input: &PreviewStackResponse{
				Stack: &StackInfo{
					Resources: []*ResourceInfo{
						{
							LogicalResourceId: "MyVpc",
							ResourceType:      "ALIYUN::ECS::VPC",
							Properties: map[string]interface{}{
								"CidrBlock": "192.168.0.0/16",
								"VpcName":   "test-vpc",
							},
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, template map[string]interface{}) {
				// Check template version
				if version, ok := template["ROSTemplateFormatVersion"].(string); !ok || version != "2015-09-01" {
					t.Errorf("ROSTemplateFormatVersion = %v, want 2015-09-01", version)
				}

				// Check resources
				resources, ok := template["Resources"].(map[string]interface{})
				if !ok {
					t.Fatal("Resources is not a map")
				}

				if len(resources) != 1 {
					t.Fatalf("len(Resources) = %d, want 1", len(resources))
				}

				vpc, ok := resources["MyVpc"].(map[string]interface{})
				if !ok {
					t.Fatal("MyVpc resource not found or wrong type")
				}

				if vpc["Type"] != "ALIYUN::ECS::VPC" {
					t.Errorf("MyVpc Type = %v, want ALIYUN::ECS::VPC", vpc["Type"])
				}

				props, ok := vpc["Properties"].(map[string]interface{})
				if !ok {
					t.Fatal("Properties not found or wrong type")
				}

				if props["CidrBlock"] != "192.168.0.0/16" {
					t.Errorf("CidrBlock = %v, want 192.168.0.0/16", props["CidrBlock"])
				}
			},
		},
		{
			name: "multiple resources with dependencies",
			input: &PreviewStackResponse{
				Stack: &StackInfo{
					Resources: []*ResourceInfo{
						{
							LogicalResourceId: "MyVpc",
							ResourceType:      "ALIYUN::ECS::VPC",
							Properties: map[string]interface{}{
								"CidrBlock": "192.168.0.0/16",
							},
						},
						{
							LogicalResourceId: "MyVSwitch",
							ResourceType:      "ALIYUN::ECS::VSwitch",
							Properties: map[string]interface{}{
								"VpcId":     "vpc-123",
								"CidrBlock": "192.168.1.0/24",
							},
							DependsOn: []string{"MyVpc"},
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, template map[string]interface{}) {
				resources := template["Resources"].(map[string]interface{})

				if len(resources) != 2 {
					t.Fatalf("len(Resources) = %d, want 2", len(resources))
				}

				vswitch, ok := resources["MyVSwitch"].(map[string]interface{})
				if !ok {
					t.Fatal("MyVSwitch resource not found")
				}

				dependsOn, ok := vswitch["DependsOn"].([]string)
				if !ok {
					t.Fatal("DependsOn not found or wrong type")
				}

				if len(dependsOn) != 1 || dependsOn[0] != "MyVpc" {
					t.Errorf("DependsOn = %v, want [MyVpc]", dependsOn)
				}
			},
		},
		{
			name: "empty resources",
			input: &PreviewStackResponse{
				Stack: &StackInfo{
					Resources: []*ResourceInfo{},
				},
			},
			wantErr: false,
			check: func(t *testing.T, template map[string]interface{}) {
				resources := template["Resources"].(map[string]interface{})
				if len(resources) != 0 {
					t.Errorf("len(Resources) = %d, want 0", len(resources))
				}
			},
		},
		{
			name:    "nil response",
			input:   nil,
			wantErr: true,
		},
		{
			name: "nil stack",
			input: &PreviewStackResponse{
				Stack: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := ConvertPreviewToTemplate(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("ConvertPreviewToTemplate() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ConvertPreviewToTemplate() error = %v, want nil", err)
			}

			if template == nil {
				t.Fatal("ConvertPreviewToTemplate() returned nil template")
			}

			if tt.check != nil {
				tt.check(t, template)
			}
		})
	}
}

func TestConvertPreviewToTemplate_DataStructureConsistency(t *testing.T) {
	// Test that the converted structure matches static analysis format
	response := &PreviewStackResponse{
		Stack: &StackInfo{
			Resources: []*ResourceInfo{
				{
					LogicalResourceId: "TestResource",
					ResourceType:      "ALIYUN::ECS::Instance",
					Properties: map[string]interface{}{
						"InstanceType": "ecs.t5-lc1m1.small",
						"ImageId":      "centos_7",
						"Tags": []interface{}{
							map[string]interface{}{
								"Key":   "env",
								"Value": "test",
							},
						},
					},
				},
			},
		},
	}

	template, err := ConvertPreviewToTemplate(response)
	if err != nil {
		t.Fatalf("ConvertPreviewToTemplate() error = %v", err)
	}

	// Verify structure matches ROS template format
	if _, ok := template["ROSTemplateFormatVersion"]; !ok {
		t.Error("Missing ROSTemplateFormatVersion")
	}

	resources, ok := template["Resources"].(map[string]interface{})
	if !ok {
		t.Fatal("Resources is not a map")
	}

	resource, ok := resources["TestResource"].(map[string]interface{})
	if !ok {
		t.Fatal("TestResource not found")
	}

	// Check Type field exists (required in ROS template)
	if _, ok := resource["Type"]; !ok {
		t.Error("Missing Type field in resource")
	}

	// Check Properties field exists and is a map
	props, ok := resource["Properties"].(map[string]interface{})
	if !ok {
		t.Fatal("Properties not found or wrong type")
	}

	// Check nested properties are preserved
	tags, ok := props["Tags"].([]interface{})
	if !ok {
		t.Fatal("Tags not found or wrong type")
	}

	if len(tags) != 1 {
		t.Errorf("len(Tags) = %d, want 1", len(tags))
	}
}

// mockError is a simple error implementation for testing
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
