package loader

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
)

func TestParseInputValues(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	kvFile := filepath.Join(tmpDir, "params.txt")
	os.WriteFile(kvFile, []byte("Key3=Value3\nKey4=Value4"), 0644)

	jsonFile := filepath.Join(tmpDir, "params.json")
	os.WriteFile(jsonFile, []byte(`{"Key5": "Value5"}`), 0644)

	tests := []struct {
		name    string
		inputs  []string
		want    models.TemplateParams
		wantErr bool
	}{
		{
			name:   "key=value format",
			inputs: []string{"Key1=Value1", "Key2=Value2"},
			want:   models.TemplateParams{"Key1": "Value1", "Key2": "Value2"},
		},
		{
			name:   "JSON format",
			inputs: []string{`{"Key1": "Value1", "Key2": 2}`},
			want:   models.TemplateParams{"Key1": "Value1", "Key2": float64(2)},
		},
		{
			name:   "KV file format",
			inputs: []string{kvFile},
			want:   models.TemplateParams{"Key3": "Value3", "Key4": "Value4"},
		},
		{
			name:   "JSON file format",
			inputs: []string{jsonFile},
			want:   models.TemplateParams{"Key5": "Value5"},
		},
		{
			name:   "Mixed formats and overrides",
			inputs: []string{"Key1=OldValue", jsonFile, "Key1=NewValue"},
			want:   models.TemplateParams{"Key1": "NewValue", "Key5": "Value5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInputValues(tt.inputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseInputValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseInputValues() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveParameters(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"InstanceType": map[string]interface{}{
				"Type":    "String",
				"Default": "ecs.t5-lc1m1.small",
			},
			"VpcId": map[string]interface{}{
				"Type": "String",
			},
			"Amount": map[string]interface{}{
				"Type":    "Number",
				"Default": 1,
			},
		},
		"Resources": map[string]interface{}{
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"InstanceType": map[string]interface{}{"Ref": "InstanceType"},
					"VpcId":        map[string]interface{}{"Ref": "VpcId"},
					"ImageId":      "ubuntu_18_04_64_20G_alibase_20190624.vhd",
					"Amount":       map[string]interface{}{"Ref": "Amount"},
				},
			},
		},
	}

	inputParams := models.TemplateParams{
		"VpcId":  "vpc-12345",
		"Amount": "2", // Should be converted to number
	}

	got, err := ResolveParameters(template, inputParams)
	if err != nil {
		t.Fatalf("ResolveParameters() error = %v", err)
	}

	// Check that parameters are resolved in the Parameters section
	params := got["Parameters"].(map[string]interface{})
	instanceTypeParam := params["InstanceType"].(map[string]interface{})
	if instanceTypeParam["ResolvedValue"] != "ecs.t5-lc1m1.small" {
		t.Errorf("InstanceType not resolved correctly in Parameters: got %v", instanceTypeParam["ResolvedValue"])
	}

	vpcIdParam := params["VpcId"].(map[string]interface{})
	if vpcIdParam["ResolvedValue"] != "vpc-12345" {
		t.Errorf("VpcId not resolved correctly in Parameters: got %v", vpcIdParam["ResolvedValue"])
	}

	amountParam := params["Amount"].(map[string]interface{})
	resolvedAmount := amountParam["ResolvedValue"]
	if resolvedAmount != 2.0 && resolvedAmount != 2 {
		t.Errorf("Amount not resolved or typed correctly in Parameters: got %v (%T)", resolvedAmount, resolvedAmount)
	}

	// Check that Resources section still contains Ref (not resolved)
	resources := got["Resources"].(map[string]interface{})
	myInstance := resources["MyInstance"].(map[string]interface{})
	properties := myInstance["Properties"].(map[string]interface{})

	// Ref should NOT be resolved - should remain as {"Ref": "..."}
	instanceTypeRef, ok := properties["InstanceType"].(map[string]interface{})
	if !ok || instanceTypeRef["Ref"] != "InstanceType" {
		t.Errorf("InstanceType Ref should be preserved: got %v", properties["InstanceType"])
	}

	vpcIdRef, ok := properties["VpcId"].(map[string]interface{})
	if !ok || vpcIdRef["Ref"] != "VpcId" {
		t.Errorf("VpcId Ref should be preserved: got %v", properties["VpcId"])
	}

	amountRef, ok := properties["Amount"].(map[string]interface{})
	if !ok || amountRef["Ref"] != "Amount" {
		t.Errorf("Amount Ref should be preserved: got %v", properties["Amount"])
	}
}

func TestResolveParameters_DefaultNull(t *testing.T) {
	// Test that Default: null (optional parameter) doesn't trigger type validation error
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"TraceSampling": map[string]interface{}{
				"Type":    "Number",
				"Default": nil, // null indicates optional parameter
			},
			"OptionalString": map[string]interface{}{
				"Type":    "String",
				"Default": nil,
			},
			"OptionalBoolean": map[string]interface{}{
				"Type":    "Boolean",
				"Default": nil,
			},
		},
		"Resources": map[string]interface{}{
			"MyResource": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"TraceSampling": map[string]interface{}{"Ref": "TraceSampling"},
				},
			},
		},
	}

	// Test with no input parameters (should use Default: null)
	got, err := ResolveParameters(template, nil)
	if err != nil {
		t.Fatalf("ResolveParameters() with Default: null should not error, got: %v", err)
	}

	resources := got["Resources"].(map[string]interface{})
	myResource := resources["MyResource"].(map[string]interface{})
	properties := myResource["Properties"].(map[string]interface{})

	// When Default is null, parameter is added to resolvedParams with nil value
	// Ref should NOT be resolved - should remain as Ref in Resources
	traceSamplingRef, ok := properties["TraceSampling"].(map[string]interface{})
	if !ok || traceSamplingRef["Ref"] != "TraceSampling" {
		t.Errorf("TraceSampling Ref should be preserved when Default is null and no input provided, got %v (%T)", properties["TraceSampling"], properties["TraceSampling"])
	}

	// Test with explicit input parameter (should validate type)
	inputParams := models.TemplateParams{
		"TraceSampling": "0.5",
	}
	got2, err := ResolveParameters(template, inputParams)
	if err != nil {
		t.Fatalf("ResolveParameters() with valid input should not error, got: %v", err)
	}

	resources2 := got2["Resources"].(map[string]interface{})
	myResource2 := resources2["MyResource"].(map[string]interface{})
	properties2 := myResource2["Properties"].(map[string]interface{})

	// Ref should NOT be resolved - should remain as Ref in Resources
	traceSamplingRef2, ok := properties2["TraceSampling"].(map[string]interface{})
	if !ok || traceSamplingRef2["Ref"] != "TraceSampling" {
		t.Errorf("TraceSampling Ref should be preserved, got %v (%T)", properties2["TraceSampling"], properties2["TraceSampling"])
	}
}

func TestResolveParameters_RefPrecedence(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"MyName": map[string]interface{}{
				"Type":    "String",
				"Default": "ParamValue",
			},
		},
		"Resources": map[string]interface{}{
			"MyName": map[string]interface{}{
				"Type": "ALIYUN::ECS::VPC",
			},
			"MyInstance": map[string]interface{}{
				"Type": "ALIYUN::ECS::Instance",
				"Properties": map[string]interface{}{
					"Prop":  map[string]interface{}{"Ref": "MyName"},
					"Other": map[string]interface{}{"Ref": "OnlyResource"},
				},
			},
			"OnlyResource": map[string]interface{}{
				"Type": "ALIYUN::ECS::VSwitch",
			},
		},
	}

	got, err := ResolveParameters(template, nil)
	if err != nil {
		t.Fatalf("ResolveParameters() error = %v", err)
	}

	resources := got["Resources"].(map[string]interface{})
	myInstance := resources["MyInstance"].(map[string]interface{})
	properties := myInstance["Properties"].(map[string]interface{})

	// Ref should NOT be resolved - should remain as Ref structure
	propRef, ok := properties["Prop"].(map[string]interface{})
	if !ok || propRef["Ref"] != "MyName" {
		t.Errorf("Prop Ref should be preserved: got %v", properties["Prop"])
	}

	// Should NOT resolve because it only exists in Resources
	other := properties["Other"].(map[string]interface{})
	if other["Ref"] != "OnlyResource" {
		t.Errorf("Should not have resolved resource ref: got %v", other)
	}
}

func TestValidateInputParameters(t *testing.T) {
	templateWithParams := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"InstanceType": map[string]interface{}{
				"Type":    "String",
				"Default": "ecs.t5-lc1m1.small",
			},
			"VpcId": map[string]interface{}{
				"Type": "String",
			},
		},
		"Resources": map[string]interface{}{},
	}

	templateWithoutParams := map[string]interface{}{
		"Resources": map[string]interface{}{},
	}

	tests := []struct {
		name        string
		template    map[string]interface{}
		inputParams models.TemplateParams
		wantErr     bool
		errContains string
	}{
		{
			name:        "single undefined parameter",
			template:    templateWithParams,
			inputParams: models.TemplateParams{"UndefinedParam": "value1"},
			wantErr:     true,
			errContains: "UndefinedParam",
		},
		{
			name:        "multiple undefined parameters",
			template:    templateWithParams,
			inputParams: models.TemplateParams{"UndefinedParam1": "value1", "UndefinedParam2": "value2"},
			wantErr:     true,
			errContains: "UndefinedParam",
		},
		{
			name:        "all valid parameters",
			template:    templateWithParams,
			inputParams: models.TemplateParams{"InstanceType": "ecs.c7.large", "VpcId": "vpc-12345"},
			wantErr:     false,
		},
		{
			name:        "mix of valid and undefined parameters",
			template:    templateWithParams,
			inputParams: models.TemplateParams{"InstanceType": "ecs.c7.large", "UndefinedParam": "value1"},
			wantErr:     true,
			errContains: "UndefinedParam",
		},
		{
			name:        "no Parameters section with no input",
			template:    templateWithoutParams,
			inputParams: models.TemplateParams{},
			wantErr:     false,
		},
		{
			name:        "no Parameters section with input provided",
			template:    templateWithoutParams,
			inputParams: models.TemplateParams{"SomeParam": "value1"},
			wantErr:     true,
			errContains: "SomeParam",
		},
		{
			name: "empty Parameters section with input",
			template: map[string]interface{}{
				"Parameters": map[string]interface{}{},
				"Resources":  map[string]interface{}{},
			},
			inputParams: models.TemplateParams{"SomeParam": "value1"},
			wantErr:     true,
			errContains: "SomeParam",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInputParameters(tt.template, tt.inputParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInputParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateInputParameters() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestValidateInputParameters_i18n(t *testing.T) {
	template := map[string]interface{}{
		"Parameters": map[string]interface{}{
			"ValidParam": map[string]interface{}{
				"Type": "String",
			},
		},
		"Resources": map[string]interface{}{},
	}

	inputParams := models.TemplateParams{"UndefinedParam": "value1"}

	// Test English
	i18n.SetLanguage("en")
	err := ValidateInputParameters(template, inputParams)
	if err == nil {
		t.Fatal("ValidateInputParameters() should return error")
	}
	if !strings.Contains(err.Error(), "UndefinedParam") {
		t.Errorf("English error message should contain parameter name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "undefined parameters") {
		t.Errorf("English error message should contain 'undefined parameters', got: %v", err)
	}

	// Test Chinese
	i18n.SetLanguage("zh")
	err = ValidateInputParameters(template, inputParams)
	if err == nil {
		t.Fatal("ValidateInputParameters() should return error")
	}
	if !strings.Contains(err.Error(), "UndefinedParam") {
		t.Errorf("Chinese error message should contain parameter name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "未定义的参数") {
		t.Errorf("Chinese error message should contain localized text, got: %v", err)
	}

	// Test no parameters defined case
	templateNoParams := map[string]interface{}{
		"Resources": map[string]interface{}{},
	}
	i18n.SetLanguage("en")
	err = ValidateInputParameters(templateNoParams, inputParams)
	if err == nil {
		t.Fatal("ValidateInputParameters() should return error")
	}
	if !strings.Contains(err.Error(), "UndefinedParam") {
		t.Errorf("Error message should contain parameter name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no parameters defined") {
		t.Errorf("English error message should contain 'no parameters defined', got: %v", err)
	}
}
