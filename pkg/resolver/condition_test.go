package resolver

import (
	"testing"
)

func TestResolveConditions_Simple(t *testing.T) {
	template := map[string]interface{}{
		"Conditions": map[string]interface{}{
			"IsProduction": map[string]interface{}{
				"Fn::Equals": []interface{}{
					map[string]interface{}{"Ref": "Environment"},
					"production",
				},
			},
		},
	}

	params := map[string]interface{}{
		"Environment": "production",
	}

	conditions, err := resolveConditions(template, params)
	if err != nil {
		t.Fatalf("resolveConditions() error = %v", err)
	}

	if !conditions["IsProduction"] {
		t.Errorf("Expected IsProduction to be true, got false")
	}
}

func TestResolveConditions_WithDependency(t *testing.T) {
	template := map[string]interface{}{
		"Conditions": map[string]interface{}{
			"IsProduction": map[string]interface{}{
				"Fn::Equals": []interface{}{
					map[string]interface{}{"Ref": "Environment"},
					"production",
				},
			},
			"EnableFeature": map[string]interface{}{
				"Fn::And": []interface{}{
					"IsProduction", // Reference to another condition
					true,
				},
			},
		},
	}

	params := map[string]interface{}{
		"Environment": "production",
	}

	conditions, err := resolveConditions(template, params)
	if err != nil {
		t.Fatalf("resolveConditions() error = %v", err)
	}

	if !conditions["IsProduction"] {
		t.Errorf("Expected IsProduction to be true, got false")
	}

	if !conditions["EnableFeature"] {
		t.Errorf("Expected EnableFeature to be true, got false")
	}
}

func TestBuildConditionGraph(t *testing.T) {
	conditions := map[string]interface{}{
		"CondA": map[string]interface{}{
			"Fn::Equals": []interface{}{"a", "a"},
		},
		"CondB": map[string]interface{}{
			"Fn::And": []interface{}{"CondA", true},
		},
		"CondC": map[string]interface{}{
			"Fn::Or": []interface{}{"CondB", false},
		},
	}

	graph := buildConditionGraph(conditions)

	if len(graph.nodes) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(graph.nodes))
	}

	// CondB depends on CondA, so CondB should have in-degree 1
	if graph.inDegree["CondB"] != 1 {
		t.Errorf("Expected CondB in-degree 1, got %d", graph.inDegree["CondB"])
	}

	// CondC depends on CondB, so CondC should have in-degree 1
	if graph.inDegree["CondC"] != 1 {
		t.Errorf("Expected CondC in-degree 1, got %d", graph.inDegree["CondC"])
	}

	// CondA has no dependencies (should be evaluated first)
	if graph.inDegree["CondA"] != 0 {
		t.Errorf("Expected CondA in-degree 0, got %d", graph.inDegree["CondA"])
	}
}

func TestTopologicalSort(t *testing.T) {
	tests := []struct {
		name    string
		graph   *conditionGraph
		wantErr bool
	}{
		{
			name: "linear dependency",
			graph: &conditionGraph{
				nodes: []string{"A", "B", "C"},
				edges: map[string][]string{
					"A": {"B"},
					"B": {"C"},
					"C": {},
				},
				inDegree: map[string]int{
					"A": 0,
					"B": 1,
					"C": 1,
				},
			},
			wantErr: false,
		},
		{
			name: "circular dependency",
			graph: &conditionGraph{
				nodes: []string{"A", "B"},
				edges: map[string][]string{
					"A": {"B"},
					"B": {"A"},
				},
				inDegree: map[string]int{
					"A": 1,
					"B": 1,
				},
			},
			wantErr: true,
		},
		{
			name: "no dependencies",
			graph: &conditionGraph{
				nodes: []string{"A", "B", "C"},
				edges: map[string][]string{
					"A": {},
					"B": {},
					"C": {},
				},
				inDegree: map[string]int{
					"A": 0,
					"B": 0,
					"C": 0,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sorted, err := topologicalSort(tt.graph)
			if (err != nil) != tt.wantErr {
				t.Errorf("topologicalSort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(sorted) != len(tt.graph.nodes) {
				t.Errorf("topologicalSort() returned %d nodes, expected %d", len(sorted), len(tt.graph.nodes))
			}
		})
	}
}

func TestApplyConditionsToResources(t *testing.T) {
	template := map[string]interface{}{
		"Resources": map[string]interface{}{
			"Resource1": map[string]interface{}{
				"Type":      "ALIYUN::ECS::Instance",
				"Condition": "IsProduction",
			},
			"Resource2": map[string]interface{}{
				"Type": "ALIYUN::ECS::VPC",
				// No condition
			},
			"Resource3": map[string]interface{}{
				"Type":      "ALIYUN::ECS::SecurityGroup",
				"Condition": "IsDevelopment",
			},
		},
	}

	conditions := map[string]bool{
		"IsProduction":  true,
		"IsDevelopment": false,
	}

	applyConditionsToResources(template, conditions)

	resources := template["Resources"].(map[string]interface{})

	// Resource1 should be kept (condition is true)
	if _, exists := resources["Resource1"]; !exists {
		t.Error("Expected Resource1 to be present")
	}

	// Resource2 should be kept (no condition)
	if _, exists := resources["Resource2"]; !exists {
		t.Error("Expected Resource2 to be present")
	}

	// Resource3 should be removed (condition is false)
	if _, exists := resources["Resource3"]; exists {
		t.Error("Expected Resource3 to be removed")
	}
}

func TestApplyConditionsToOutputs(t *testing.T) {
	template := map[string]interface{}{
		"Outputs": map[string]interface{}{
			"Output1": map[string]interface{}{
				"Value":     "value1",
				"Condition": "IsProduction",
			},
			"Output2": map[string]interface{}{
				"Value": "value2",
				// No condition
			},
			"Output3": map[string]interface{}{
				"Value":     "value3",
				"Condition": "IsDevelopment",
			},
		},
	}

	conditions := map[string]bool{
		"IsProduction":  true,
		"IsDevelopment": false,
	}

	applyConditionsToOutputs(template, conditions)

	outputs := template["Outputs"].(map[string]interface{})

	// Output1 should be kept (condition is true)
	if _, exists := outputs["Output1"]; !exists {
		t.Error("Expected Output1 to be present")
	}

	// Output2 should be kept (no condition)
	if _, exists := outputs["Output2"]; !exists {
		t.Error("Expected Output2 to be present")
	}

	// Output3 should be removed (condition is false)
	if _, exists := outputs["Output3"]; exists {
		t.Error("Expected Output3 to be removed")
	}
}

func TestResolveConditionsAndFunctions(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"Environment": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "production",
			},
		},
		"Conditions": map[string]interface{}{
			"IsProduction": map[string]interface{}{
				"Fn::Equals": []interface{}{
					map[string]interface{}{"Ref": "Environment"},
					"production",
				},
			},
		},
		"Resources": map[string]interface{}{
			"ProdInstance": map[string]interface{}{
				"Type":      "ALIYUN::ECS::Instance",
				"Condition": "IsProduction",
				"Properties": map[string]interface{}{
					"Name": map[string]interface{}{
						"Fn::Join": []interface{}{"-", []interface{}{"prod", "server"}},
					},
				},
			},
			"DevInstance": map[string]interface{}{
				"Type":      "ALIYUN::ECS::Instance",
				"Condition": "IsDevelopment",
			},
		},
	}

	result := ResolveConditionsAndFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})

	// ProdInstance should be present (IsProduction is true)
	if _, exists := resources["ProdInstance"]; !exists {
		t.Error("Expected ProdInstance to be present")
	} else {
		// Check that functions were resolved
		prodInstance := resources["ProdInstance"].(map[string]interface{})
		props := prodInstance["Properties"].(map[string]interface{})
		if props["Name"] != "prod-server" {
			t.Errorf("Expected Name to be 'prod-server', got %v", props["Name"])
		}
	}

	// DevInstance should be removed (IsDevelopment doesn't exist/is false)
	if _, exists := resources["DevInstance"]; exists {
		t.Error("Expected DevInstance to be removed")
	}
}

func TestResolveConditionsAndFunctions_WithFnIf(t *testing.T) {
	// Test case based on user report: Fn::If should resolve condition correctly
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"ENV": map[string]interface{}{
				"Type":          "String",
				"ResolvedValue": "test",
			},
		},
		"Conditions": map[string]interface{}{
			"TestEnv": map[string]interface{}{
				"Fn::Equals": []interface{}{
					"test",
					map[string]interface{}{"Ref": "ENV"},
				},
			},
		},
		"Resources": map[string]interface{}{
			"VSwitch_N_NGW": map[string]interface{}{
				"Type": "ALIYUN::ECS::VSwitch",
				"Properties": map[string]interface{}{
					"VSwitchName": map[string]interface{}{
						"Fn::If": []interface{}{
							"TestEnv",
							"this is test",
							map[string]interface{}{
								"Fn::Sub": []interface{}{
									"${ENV}-sh-n-vswt-ngw-01",
									map[string]interface{}{},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ResolveConditionsAndFunctions(template, map[string]interface{}{})

	resources := result["Resources"].(map[string]interface{})
	vswitch := resources["VSwitch_N_NGW"].(map[string]interface{})
	props := vswitch["Properties"].(map[string]interface{})

	// Since TestEnv is true (ENV is "test"), VSwitchName should be "this is test"
	if props["VSwitchName"] != "this is test" {
		t.Errorf("Expected VSwitchName to be 'this is test', got %v", props["VSwitchName"])
	}
}

// Integration tests for condition dependencies

func TestResolveConditions_MultiLevelDependency(t *testing.T) {
	template := map[string]interface{}{
		"Conditions": map[string]interface{}{
			"CondA": map[string]interface{}{
				"Fn::Equals": []interface{}{"a", "a"},
			},
			"CondB": map[string]interface{}{
				"Fn::And": []interface{}{"CondA", true},
			},
			"CondC": map[string]interface{}{
				"Fn::And": []interface{}{"CondB", true},
			},
		},
	}

	conditions, err := resolveConditions(template, map[string]interface{}{})
	if err != nil {
		t.Fatalf("resolveConditions() error = %v", err)
	}

	if !conditions["CondA"] {
		t.Errorf("Expected CondA to be true")
	}
	if !conditions["CondB"] {
		t.Errorf("Expected CondB to be true")
	}
	if !conditions["CondC"] {
		t.Errorf("Expected CondC to be true")
	}
}

func TestResolveConditions_CircularDependency(t *testing.T) {
	template := map[string]interface{}{
		"Conditions": map[string]interface{}{
			"CondA": map[string]interface{}{
				"Fn::And": []interface{}{"CondB", true},
			},
			"CondB": map[string]interface{}{
				"Fn::And": []interface{}{"CondA", true},
			},
		},
	}

	_, err := resolveConditions(template, map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for circular dependency, got nil")
	}
}

func TestResolveConditions_ComplexLogic(t *testing.T) {
	template := map[string]interface{}{
		"Conditions": map[string]interface{}{
			"IsProduction": map[string]interface{}{
				"Fn::Equals": []interface{}{
					map[string]interface{}{"Ref": "Env"},
					"prod",
				},
			},
			"IsDevelopment": map[string]interface{}{
				"Fn::Equals": []interface{}{
					map[string]interface{}{"Ref": "Env"},
					"dev",
				},
			},
			"EnableHighAvailability": map[string]interface{}{
				"Fn::Or": []interface{}{
					"IsProduction",
					map[string]interface{}{
						"Fn::Equals": []interface{}{
							map[string]interface{}{"Ref": "HA"},
							"true",
						},
					},
				},
			},
		},
	}

	params := map[string]interface{}{
		"Env": "dev",
		"HA":  "true",
	}

	conditions, err := resolveConditions(template, params)
	if err != nil {
		t.Fatalf("resolveConditions() error = %v", err)
	}

	if conditions["IsProduction"] {
		t.Errorf("Expected IsProduction to be false")
	}
	if !conditions["IsDevelopment"] {
		t.Errorf("Expected IsDevelopment to be true")
	}
	// EnableHighAvailability should be true (HA parameter is true)
	if !conditions["EnableHighAvailability"] {
		t.Errorf("Expected EnableHighAvailability to be true")
	}
}
