package resolver

import (
	"reflect"
	"testing"
)

func TestResolveRef_Parameter(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"InstanceType": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "ecs.c6.large",
			},
		},
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"InstanceType": map[string]interface{}{"Ref": "InstanceType"},
				},
			},
		},
	}

	params := map[string]interface{}{"InstanceType": "ecs.c6.large"}
	result := ResolveFunctions(template, params)

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["InstanceType"] != "ecs.c6.large" {
		t.Errorf("Expected InstanceType to be resolved to 'ecs.c6.large', got %v", props["InstanceType"])
	}
}

func TestResolveRef_Resource(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyVpc": map[string]interface{}{
				"Type": "ALIYUN::ECS::VPC",
			},
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"VpcId": map[string]interface{}{"Ref": "MyVpc"},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	// Resource refs should be kept as-is
	vpcId, ok := props["VpcId"].(map[string]interface{})
	if !ok || vpcId["Ref"] != "MyVpc" {
		t.Errorf("Expected VpcId Ref to be preserved, got %v", props["VpcId"])
	}
}

func TestResolveFnJoin(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"InstanceName": map[string]interface{}{
						"Fn::Join": []interface{}{"-", []interface{}{"web", "server", "prod"}},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["InstanceName"] != "web-server-prod" {
		t.Errorf("Expected InstanceName to be 'web-server-prod', got %v", props["InstanceName"])
	}
}

func TestResolveFnSub_Simple(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"Name": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "MyApp",
			},
		},
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Description": map[string]interface{}{
						"Fn::Sub": "Instance for ${Name}",
					},
				},
			},
		},
	}

	params := map[string]interface{}{"Name": "MyApp"}
	result := ResolveFunctions(template, params)

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["Description"] != "Instance for MyApp" {
		t.Errorf("Expected Description to be 'Instance for MyApp', got %v", props["Description"])
	}
}

func TestResolveFnSub_WithVariables(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Description": map[string]interface{}{
						"Fn::Sub": []interface{}{
							"${Env}-${App}",
							map[string]interface{}{
								"Env": "prod",
								"App": "web",
							},
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["Description"] != "prod-web" {
		t.Errorf("Expected Description to be 'prod-web', got %v", props["Description"])
	}
}

func TestResolveFnBase64Encode(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"UserData": map[string]interface{}{
						"Fn::Base64Encode": "#!/bin/bash\necho hello",
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	expected := "IyEvYmluL2Jhc2gKZWNobyBoZWxsbw=="
	if props["UserData"] != expected {
		t.Errorf("Expected UserData to be base64 encoded, got %v", props["UserData"])
	}
}

func TestResolveNestedFunctions(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"Prefix": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "myapp",
			},
		},
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"InstanceName": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{
								map[string]interface{}{"Ref": "Prefix"},
								"server",
								"prod",
							},
						},
					},
				},
			},
		},
	}

	params := map[string]interface{}{"Prefix": "myapp"}
	result := ResolveFunctions(template, params)

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["InstanceName"] != "myapp-server-prod" {
		t.Errorf("Expected nested functions to resolve to 'myapp-server-prod', got %v", props["InstanceName"])
	}
}

func TestUnresolvableFunctions_Preserved(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Endpoint": map[string]interface{}{
						"Fn::GetAtt": []interface{}{"MyDB", "ConnectionString"},
					},
					"Region": map[string]interface{}{
						"Fn::GetAZs": "cn-hangzhou",
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	// GetAtt should be preserved
	endpoint, ok := props["Endpoint"].(map[string]interface{})
	if !ok || endpoint["Fn::GetAtt"] == nil {
		t.Errorf("Expected Fn::GetAtt to be preserved, got %v", props["Endpoint"])
	}

	// GetAZs should be preserved
	region, ok := props["Region"].(map[string]interface{})
	if !ok || region["Fn::GetAZs"] == nil {
		t.Errorf("Expected Fn::GetAZs to be preserved, got %v", props["Region"])
	}
}

func TestResolveRef_NonExistent(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{"Ref": "NonExistent"},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	// Non-existent ref should be preserved
	value, ok := props["Value"].(map[string]interface{})
	if !ok || value["Ref"] != "NonExistent" {
		t.Errorf("Expected non-existent Ref to be preserved, got %v", props["Value"])
	}
}

func TestComplexNestedScenario(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"Env": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "production",
			},
			"AppName": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "webapp",
			},
		},
		"Resources": map[string]interface{}{
			"MyDB": map[string]interface{}{
				"Type": "ALIYUN::RDS::DBInstance",
			},
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"InstanceName": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{
								map[string]interface{}{"Ref": "Env"},
								map[string]interface{}{"Ref": "AppName"},
								"server",
							},
						},
					},
					"Description": map[string]interface{}{
						"Fn::Sub": "Server for ${AppName} in ${Env}",
					},
					"UserData": map[string]interface{}{
						"Fn::Base64Encode": map[string]interface{}{
							"Fn::Sub": "#!/bin/bash\nAPP=${AppName}",
						},
					},
					"DBEndpoint": map[string]interface{}{
						"Fn::GetAtt": []interface{}{"MyDB", "ConnectionString"},
					},
					"VpcId": map[string]interface{}{"Ref": "MyDB"},
				},
			},
		},
	}

	params := map[string]interface{}{
		"Env":     "production",
		"AppName": "webapp",
	}
	result := ResolveFunctions(template, params)

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	// Check InstanceName (nested Join with Refs)
	if props["InstanceName"] != "production-webapp-server" {
		t.Errorf("Expected InstanceName to be 'production-webapp-server', got %v", props["InstanceName"])
	}

	// Check Description (Sub)
	if props["Description"] != "Server for webapp in production" {
		t.Errorf("Expected Description to be 'Server for webapp in production', got %v", props["Description"])
	}

	// Check UserData (nested Base64Encode with Sub)
	// Should be base64 of "#!/bin/bash\nAPP=webapp"
	if _, ok := props["UserData"].(string); !ok {
		t.Errorf("Expected UserData to be a base64 string, got %v (%T)", props["UserData"], props["UserData"])
	}

	// Check DBEndpoint (GetAtt should be preserved)
	dbEndpoint, ok := props["DBEndpoint"].(map[string]interface{})
	if !ok || dbEndpoint["Fn::GetAtt"] == nil {
		t.Errorf("Expected DBEndpoint Fn::GetAtt to be preserved, got %v", props["DBEndpoint"])
	}

	// Check VpcId (Resource Ref should be preserved)
	vpcId, ok := props["VpcId"].(map[string]interface{})
	if !ok || vpcId["Ref"] != "MyDB" {
		t.Errorf("Expected VpcId Ref to MyDB to be preserved, got %v", props["VpcId"])
	}
}

func TestResolveFnSelect(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"AZ": map[string]interface{}{
						"Fn::Select": []interface{}{
							1,
							[]interface{}{"cn-hangzhou-a", "cn-hangzhou-b", "cn-hangzhou-c"},
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["AZ"] != "cn-hangzhou-b" {
		t.Errorf("Expected AZ to be 'cn-hangzhou-b', got %v", props["AZ"])
	}
}

func TestResolveFnSplit(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Tags": map[string]interface{}{
						"Fn::Split": []interface{}{",", "tag1,tag2,tag3"},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	tags, ok := props["Tags"].([]interface{})
	if !ok || len(tags) != 3 {
		t.Errorf("Expected Tags to be a 3-element array, got %v", props["Tags"])
	}

	expected := []string{"tag1", "tag2", "tag3"}
	for i, tag := range tags {
		if tag != expected[i] {
			t.Errorf("Expected tag[%d] to be '%s', got %v", i, expected[i], tag)
		}
	}
}

func TestDeepCopy(t *testing.T) {
	original := map[string]interface{}{
		"key1": "value1",
		"key2": map[string]interface{}{
			"nested": "value2",
		},
		"key3": []interface{}{1, 2, 3},
	}

	copied := deepCopy(original).(map[string]interface{})

	// Modify the copy
	copied["key1"] = "modified"
	copied["key2"].(map[string]interface{})["nested"] = "modified"
	copied["key3"].([]interface{})[0] = 999

	// Original should be unchanged
	if original["key1"] != "value1" {
		t.Errorf("Original was modified")
	}
	if original["key2"].(map[string]interface{})["nested"] != "value2" {
		t.Errorf("Original nested map was modified")
	}
	if original["key3"].([]interface{})[0] != 1 {
		t.Errorf("Original array was modified")
	}
}

func TestExtractResolvedParams(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"Param1": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "value1",
			},
			"Param2": map[string]interface{}{
				"Type":    "String",
				"Default": "default2",
				// No ResolvedValue
			},
			"Param3": map[string]interface{}{
				"Type":          "Number",
				"ResolvedValue": 42,
			},
		},
	}

	params := extractResolvedParams(template)

	if params["Param1"] != "value1" {
		t.Errorf("Expected Param1 to be 'value1', got %v", params["Param1"])
	}

	if _, exists := params["Param2"]; exists {
		t.Errorf("Param2 should not be in resolved params (no ResolvedValue)")
	}

	if params["Param3"] != 42 {
		t.Errorf("Expected Param3 to be 42, got %v", params["Param3"])
	}
}

func TestMixedResolvedAndUnresolved(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"CanResolve": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "resolved",
			},
		},
		"Resources": map[string]interface{}{
			"MyVpc": map[string]interface{}{
				"Type": "ALIYUN::ECS::VPC",
			},
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Name": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{
								map[string]interface{}{"Ref": "CanResolve"},
								"server",
							},
						},
					},
					"VpcId": map[string]interface{}{"Ref": "MyVpc"},
					"Endpoint": map[string]interface{}{
						"Fn::GetAtt": []interface{}{"MyVpc", "VpcId"},
					},
				},
			},
		},
	}

	params := map[string]interface{}{"CanResolve": "resolved"}
	result := ResolveFunctions(template, params)

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	// Name should be resolved (Join with Ref to parameter)
	if props["Name"] != "resolved-server" {
		t.Errorf("Expected Name to be 'resolved-server', got %v", props["Name"])
	}

	// VpcId should be preserved (Ref to resource)
	vpcId, ok := props["VpcId"].(map[string]interface{})
	if !ok || vpcId["Ref"] != "MyVpc" {
		t.Errorf("Expected VpcId Ref to be preserved, got %v", props["VpcId"])
	}

	// Endpoint should be preserved (GetAtt)
	endpoint, ok := props["Endpoint"].(map[string]interface{})
	if !ok || endpoint["Fn::GetAtt"] == nil {
		t.Errorf("Expected Endpoint GetAtt to be preserved, got %v", props["Endpoint"])
	}
}

func TestIsFunction(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{
			name:     "Ref function",
			value:    map[string]interface{}{"Ref": "MyParam"},
			expected: true,
		},
		{
			name:     "Fn::Join function",
			value:    map[string]interface{}{"Fn::Join": []interface{}{"-", []interface{}{"a", "b"}}},
			expected: true,
		},
		{
			name:     "Regular map",
			value:    map[string]interface{}{"key1": "value1", "key2": "value2"},
			expected: false,
		},
		{
			name:     "String",
			value:    "just a string",
			expected: false,
		},
		{
			name:     "Empty map",
			value:    map[string]interface{}{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFunction(tt.value)
			if result != tt.expected {
				t.Errorf("isFunction(%v) = %v, expected %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestSubstituteVariables_Literal(t *testing.T) {
	// Test ${!Literal} which should become ${Literal}
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Sub": "Path: ${!Literal}/data",
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "Path: ${Literal}/data"
	if props["Value"] != expected {
		t.Errorf("Expected ${!Literal} to become ${Literal}, got %v", props["Value"])
	}
}

func TestSubstituteVariables_PseudoParameter(t *testing.T) {
	// Pseudo parameters cannot be resolved statically
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Sub": "Stack: ${ALIYUN::StackId}",
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	// Should return as-is (wrapped in Fn::Sub)
	subMap, ok := props["Value"].(map[string]interface{})
	if !ok || subMap["Fn::Sub"] != "Stack: ${ALIYUN::StackId}" {
		t.Errorf("Expected pseudo parameter to be preserved, got %v", props["Value"])
	}
}

func TestSubstituteVariables_ResourceAttribute(t *testing.T) {
	// Resource attributes cannot be resolved statically
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Sub": "ARN: ${MyResource.Arn}",
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	// Should return as-is (wrapped in Fn::Sub)
	subMap, ok := props["Value"].(map[string]interface{})
	if !ok || subMap["Fn::Sub"] != "ARN: ${MyResource.Arn}" {
		t.Errorf("Expected resource attribute to be preserved, got %v", props["Value"])
	}
}

func TestResolveFunctionsWithParametersSection(t *testing.T) {
	// Test that resolved values are extracted from Parameters section
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"MyParam": map[string]interface{}{
				"Type":          "String",
				"Default":       "default",
				"ResolvedValue": "actual",
			},
		},
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{"Ref": "MyParam"},
				},
			},
		},
	}

	// Don't pass params explicitly - should use ResolvedValue from Parameters
	result := ResolveFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	if props["Value"] != "actual" {
		t.Errorf("Expected Value to use ResolvedValue from Parameters, got %v", props["Value"])
	}
}

func TestResolveValue_Scalar(t *testing.T) {
	// Test that scalar values are returned as-is
	tests := []interface{}{
		"string",
		123,
		45.67,
		true,
		false,
		nil,
	}

	for _, test := range tests {
		result, err := resolveValue(test, map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			t.Fatalf("Unexpected error for %v: %v", test, err)
		}
		if !reflect.DeepEqual(result, test) {
			t.Errorf("Expected scalar %v to be unchanged, got %v", test, result)
		}
	}
}

// Benchmarks

func BenchmarkResolveFunctions(b *testing.B) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"Env": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "prod",
			},
			"AppName": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "web-server",
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
				},
			},
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"InstanceName": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{
								map[string]interface{}{"Ref": "Env"},
								map[string]interface{}{"Ref": "AppName"},
							},
						},
					},
					"UserData": map[string]interface{}{
						"Fn::Base64Encode": map[string]interface{}{
							"Fn::Sub": "#!/bin/bash\necho ${Env}\n",
						},
					},
				},
			},
		},
	}

	params := map[string]interface{}{
		"Env":     "prod",
		"AppName": "web-server",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ResolveFunctions(template, params)
	}
}

func BenchmarkResolveValue_DeepNesting(b *testing.B) {
	// Create a deeply nested structure
	value := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": map[string]interface{}{
					"level4": map[string]interface{}{
						"value": "test",
					},
				},
			},
		},
	}

	params := map[string]interface{}{}
	template := map[string]interface{}{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolveValue(value, params, template)
	}
}

func BenchmarkResolveFnJoin(b *testing.B) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Join": []interface{}{
							"-",
							[]interface{}{"part1", "part2", "part3"},
						},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ResolveFunctions(template, map[string]interface{}{})
	}
}

// Test string functions

func TestResolveFnBase64Decode(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Base64Decode": "SGVsbG8gV29ybGQ=",
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "Hello World"
	if props["Value"] != expected {
		t.Errorf("Expected Value to be %q, got %v", expected, props["Value"])
	}
}

func TestResolveFnStr(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Str": 42,
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "42"
	if props["Value"] != expected {
		t.Errorf("Expected Value to be %q, got %v", expected, props["Value"])
	}
}

func TestResolveFnIndent(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Indent": []interface{}{2, "line1\nline2"},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "  line1\n  line2"
	if props["Value"] != expected {
		t.Errorf("Expected Value to be %q, got %q", expected, props["Value"])
	}
}

func TestResolveFnReplace(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Replace": []interface{}{
							map[string]interface{}{"old": "new"},
							"old text",
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "new text"
	if props["Value"] != expected {
		t.Errorf("Expected Value to be %q, got %v", expected, props["Value"])
	}
}

func TestNestedStringFunctions(t *testing.T) {
	// Test Fn::Base64Decode(Fn::Base64Encode("test"))
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::Base64Decode": map[string]interface{}{
							"Fn::Base64Encode": "test",
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "test"
	if props["Value"] != expected {
		t.Errorf("Expected nested Base64 functions to return %q, got %v", expected, props["Value"])
	}
}

// Test list functions

func TestResolveFnIndex(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Index": map[string]interface{}{
						"Fn::Index": []interface{}{
							[]interface{}{"a", "b", "c"},
							"b",
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := 1
	if props["Index"] != expected {
		t.Errorf("Expected Index to be %v, got %v", expected, props["Index"])
	}
}

func TestResolveFnLength(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected int
	}{
		{
			name:     "string length",
			value:    []interface{}{"hello"},
			expected: 5,
		},
		{
			name:     "list length",
			value:    []interface{}{[]interface{}{1, 2, 3}},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := map[string]interface{}{
				"Resources": map[string]interface{}{
					"MyResource": map[string]interface{}{
						"Properties": map[string]interface{}{
							"Length": map[string]interface{}{
								"Fn::Length": tt.value,
							},
						},
					},
				},
			}

			result := ResolveFunctions(template, map[string]interface{}{})
			resources := result["Resources"].(map[string]interface{})
			resource := resources["MyResource"].(map[string]interface{})
			props := resource["Properties"].(map[string]interface{})

			if props["Length"] != tt.expected {
				t.Errorf("Expected Length to be %v, got %v", tt.expected, props["Length"])
			}
		})
	}
}

func TestResolveFnListMerge(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"List": map[string]interface{}{
						"Fn::ListMerge": []interface{}{
							[]interface{}{"a", "b"},
							[]interface{}{"c", "d"},
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := []interface{}{"a", "b", "c", "d"}
	actual, ok := props["List"].([]interface{})
	if !ok {
		t.Fatalf("Expected List to be a slice, got %T", props["List"])
	}

	if len(actual) != len(expected) {
		t.Errorf("Expected List length %v, got %v", len(expected), len(actual))
	}

	for i, v := range actual {
		if v != expected[i] {
			t.Errorf("Expected List[%d] to be %v, got %v", i, expected[i], v)
		}
	}
}

func TestResolveFnSelectMapList(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Values": map[string]interface{}{
						"Fn::SelectMapList": []interface{}{
							"key",
							[]interface{}{
								map[string]interface{}{"key": "v1", "other": "x"},
								map[string]interface{}{"key": "v2", "other": "y"},
							},
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := []interface{}{"v1", "v2"}
	actual, ok := props["Values"].([]interface{})
	if !ok {
		t.Fatalf("Expected Values to be a slice, got %T", props["Values"])
	}

	if len(actual) != len(expected) {
		t.Errorf("Expected Values length %v, got %v", len(expected), len(actual))
	}

	for i, v := range actual {
		if v != expected[i] {
			t.Errorf("Expected Values[%d] to be %v, got %v", i, expected[i], v)
		}
	}
}

func TestListFunctionsBoundary(t *testing.T) {
	tests := []struct {
		name     string
		function string
		value    interface{}
	}{
		{
			name:     "empty list in Index",
			function: "Fn::Index",
			value:    []interface{}{[]interface{}{}, "x"},
		},
		{
			name:     "empty list in ListMerge",
			function: "Fn::ListMerge",
			value:    []interface{}{[]interface{}{}, []interface{}{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := map[string]interface{}{
				"Resources": map[string]interface{}{
					"MyResource": map[string]interface{}{
						"Properties": map[string]interface{}{
							"Value": map[string]interface{}{
								tt.function: tt.value,
							},
						},
					},
				},
			}

			// Should not panic or error
			result := ResolveFunctions(template, map[string]interface{}{})
			if result == nil {
				t.Error("Expected result to not be nil")
			}
		})
	}
}

// Test map functions

func TestResolveFnFindInMap(t *testing.T) {
	template := map[string]interface{}{
		"Mappings": map[string]interface{}{
			"RegionMap": map[string]interface{}{
				"cn-hangzhou": map[string]interface{}{
					"AMI": "ami-12345",
				},
			},
		},
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Properties": map[string]interface{}{
					"ImageId": map[string]interface{}{
						"Fn::FindInMap": []interface{}{"RegionMap", "cn-hangzhou", "AMI"},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	instance := resources["MyInstance"].(map[string]interface{})
	props := instance["Properties"].(map[string]interface{})

	expected := "ami-12345"
	if props["ImageId"] != expected {
		t.Errorf("Expected ImageId to be %q, got %v", expected, props["ImageId"])
	}
}

func TestResolveFnGetJsonValue(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"Value": map[string]interface{}{
						"Fn::GetJsonValue": []interface{}{"key", `{"key": "value", "num": 123}`},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	expected := "value"
	if props["Value"] != expected {
		t.Errorf("Expected Value to be %q, got %v", expected, props["Value"])
	}
}

func TestResolveFnMergeMapToList(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Properties": map[string]interface{}{
					"List": map[string]interface{}{
						"Fn::MergeMapToList": []interface{}{
							[]interface{}{
								map[string]interface{}{"k1": "v1"},
								map[string]interface{}{"k1": "v3"},
							},
							[]interface{}{
								map[string]interface{}{"k2": "v2"},
								map[string]interface{}{"k2": "v4"},
							},
						},
					},
				},
			},
		},
	}

	result := ResolveFunctions(template, map[string]interface{}{})
	resources := result["Resources"].(map[string]interface{})
	resource := resources["MyResource"].(map[string]interface{})
	props := resource["Properties"].(map[string]interface{})

	resultList, ok := props["List"].([]interface{})
	if !ok {
		t.Fatalf("Expected List to be a slice, got %T", props["List"])
	}

	if len(resultList) != 2 {
		t.Errorf("Expected List length 2, got %v", len(resultList))
	}

	// Check first merged map
	firstMap, ok := resultList[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected first item to be a map, got %T", resultList[0])
	}
	if firstMap["k1"] != "v1" || firstMap["k2"] != "v2" {
		t.Errorf("First map incorrect: %v", firstMap)
	}

	// Check second merged map
	secondMap, ok := resultList[1].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected second item to be a map, got %T", resultList[1])
	}
	if secondMap["k1"] != "v3" || secondMap["k2"] != "v4" {
		t.Errorf("Second map incorrect: %v", secondMap)
	}
}
