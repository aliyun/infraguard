package resolver

import (
	"fmt"
	"testing"
)

// Integration test to verify the full resolution pipeline
func TestIntegration_FullResolution(t *testing.T) {
	// Simulate a template as it would come from loader after parameter resolution
	template := map[string]interface{}{
		"ROSTemplateFormatVersion": "2015-09-01",
		"Parameters": map[string]interface{}{
			"Env": map[string]interface{}{
				"Type":          "String",
				"Default":       "prod",
				"ResolvedValue": "prod",
			},
			"App": map[string]interface{}{
				"Type":          "String",
				"Default":       "web",
				"ResolvedValue": "web",
			},
		},
		"Resources": map[string]interface{}{
			"MyVpc": map[string]interface{}{
				"Type": "ALIYUN::ECS::VPC",
				"Properties": map[string]interface{}{
					"VpcName": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{
								map[string]interface{}{"Ref": "Env"},
								"vpc",
							},
						},
					},
					"Description": map[string]interface{}{
						"Fn::Sub": "VPC for ${App}",
					},
				},
			},
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"VpcId": map[string]interface{}{"Ref": "MyVpc"},
					"InstanceName": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{
								map[string]interface{}{"Ref": "Env"},
								map[string]interface{}{"Ref": "App"},
								"server",
							},
						},
					},
					"UserData": map[string]interface{}{
						"Fn::Base64Encode": map[string]interface{}{
							"Fn::Sub": "#!/bin/bash\nAPP=${App}",
						},
					},
					"Endpoint": map[string]interface{}{
						"Fn::GetAtt": []interface{}{"MyDB", "ConnectionString"},
					},
				},
			},
			"MyDB": map[string]interface{}{
				"Type": "ALIYUN::RDS::DBInstance",
			},
		},
		"Outputs": map[string]interface{}{
			"VpcId": map[string]interface{}{
				"Value": map[string]interface{}{"Ref": "MyVpc"},
			},
			"InstanceName": map[string]interface{}{
				"Value": map[string]interface{}{
					"Fn::Join": []interface{}{
						"-",
						[]interface{}{
							map[string]interface{}{"Ref": "Env"},
							map[string]interface{}{"Ref": "App"},
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, nil)

	// Verify VpcName is resolved
	vpc := result["Resources"].(map[string]interface{})["MyVpc"].(map[string]interface{})
	vpcProps := vpc["Properties"].(map[string]interface{})
	if vpcProps["VpcName"] != "prod-vpc" {
		t.Errorf("VpcName should be 'prod-vpc', got %v", vpcProps["VpcName"])
	}

	// Verify Description is resolved
	if vpcProps["Description"] != "VPC for web" {
		t.Errorf("Description should be 'VPC for web', got %v", vpcProps["Description"])
	}

	// Verify InstanceName is resolved
	instance := result["Resources"].(map[string]interface{})["MyInstance"].(map[string]interface{})
	instanceProps := instance["Properties"].(map[string]interface{})
	if instanceProps["InstanceName"] != "prod-web-server" {
		t.Errorf("InstanceName should be 'prod-web-server', got %v", instanceProps["InstanceName"])
	}

	// Verify VpcId is preserved (resource reference)
	vpcId, ok := instanceProps["VpcId"].(map[string]interface{})
	if !ok || vpcId["Ref"] != "MyVpc" {
		t.Errorf("VpcId should preserve Ref to MyVpc, got %v", instanceProps["VpcId"])
	}

	// Verify UserData is base64 encoded (nested Sub then Base64)
	userData, ok := instanceProps["UserData"].(string)
	if !ok {
		t.Errorf("UserData should be a base64 string, got %v (%T)", instanceProps["UserData"], instanceProps["UserData"])
	}
	if userData == "" {
		t.Errorf("UserData should not be empty")
	}

	// Verify Endpoint is preserved (GetAtt)
	endpoint, ok := instanceProps["Endpoint"].(map[string]interface{})
	if !ok || endpoint["Fn::GetAtt"] == nil {
		t.Errorf("Endpoint should preserve Fn::GetAtt, got %v", instanceProps["Endpoint"])
	}

	// Verify Outputs
	outputs := result["Outputs"].(map[string]interface{})

	// VpcId output should preserve resource Ref
	vpcIdOutput := outputs["VpcId"].(map[string]interface{})
	vpcIdValue, ok := vpcIdOutput["Value"].(map[string]interface{})
	if !ok || vpcIdValue["Ref"] != "MyVpc" {
		t.Errorf("VpcId output should preserve Ref, got %v", vpcIdOutput["Value"])
	}

	// InstanceName output should be resolved
	instanceNameOutput := outputs["InstanceName"].(map[string]interface{})
	if instanceNameOutput["Value"] != "prod-web" {
		t.Errorf("InstanceName output should be 'prod-web', got %v", instanceNameOutput["Value"])
	}

	// Print diagnostic info
	t.Logf("VpcName resolved to: %v", vpcProps["VpcName"])
	t.Logf("InstanceName resolved to: %v", instanceProps["InstanceName"])
	t.Logf("UserData length: %d bytes", len(userData))
	t.Logf("Endpoint preserved: %v", endpoint)
}

// Test to ensure that resolver doesn't crash on edge cases
func TestIntegration_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		template map[string]interface{}
	}{
		{
			name: "Empty template",
			template: map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources":                map[string]interface{}{},
			},
		},
		{
			name: "No parameters",
			template: map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"Resource1": map[string]interface{}{
						"Type": "ALIYUN::ECS::VPC",
					},
				},
			},
		},
		{
			name: "Only unresolvable functions",
			template: map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"Resource1": map[string]interface{}{
						"Type": "ALIYUN::ECS::Instance",
						"Properties": map[string]interface{}{
							"Value": map[string]interface{}{
								"Fn::GetAtt": []interface{}{"DB", "Endpoint"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic or error
			result := ResolveFunctions(tt.template, nil)
			if result == nil {
				t.Errorf("ResolveFunctions returned nil")
			}
		})
	}
}

func ExampleResolveFunctions() {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"AppName": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "myapp",
			},
		},
		"Resources": map[string]interface{}{
			"Instance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Name": map[string]interface{}{
						"Fn::Join": []interface{}{"-", []interface{}{
							map[string]interface{}{"Ref": "AppName"},
							"server",
						}},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, nil)

	instance := result["Resources"].(map[string]interface{})["Instance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	fmt.Printf("Resolved Name: %v\n", props["Name"])
	// Output: Resolved Name: myapp-server
}
