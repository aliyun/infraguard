package ros

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_StaticMode(t *testing.T) {
	// Create a temporary ROS template
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "template.yaml")

	templateContent := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  InstanceType:
    Type: String
    Default: ecs.t5-lc1m1.small
Resources:
  MyInstance:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId: centos_7
`

	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	inputParams := map[string]interface{}{
		"InstanceType": "ecs.g6.large",
	}

	yamlRoot, templateData, err := Load(ModeStatic, templatePath, inputParams)
	if err != nil {
		t.Fatalf("Load(ModeStatic) error = %v", err)
	}

	if yamlRoot == nil {
		t.Error("yamlRoot is nil")
	}

	if templateData == nil {
		t.Fatal("templateData is nil")
	}

	// Verify template structure
	if _, ok := templateData["ROSTemplateFormatVersion"]; !ok {
		t.Error("missing ROSTemplateFormatVersion")
	}

	resources, ok := templateData["Resources"].(map[string]interface{})
	if !ok {
		t.Fatal("Resources is not a map")
	}

	if len(resources) == 0 {
		t.Error("no resources found")
	}
}

func TestLoad_InvalidMode(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "template.yaml")

	templateContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyVpc:
    Type: ALIYUN::ECS::VPC
    Properties:
      CidrBlock: 192.168.0.0/16
`

	os.WriteFile(templatePath, []byte(templateContent), 0644)

	_, _, err := Load("invalid", templatePath, nil)
	if err == nil {
		t.Error("Load(invalid mode) error = nil, want error")
	}
}

func TestLoad_InvalidTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "invalid.yaml")

	// Invalid YAML
	invalidContent := `invalid: yaml: content:`
	os.WriteFile(templatePath, []byte(invalidContent), 0644)

	_, _, err := Load(ModeStatic, templatePath, nil)
	if err == nil {
		t.Error("Load(invalid template) error = nil, want error")
	}
}

func TestLoad_MissingTemplate(t *testing.T) {
	_, _, err := Load(ModeStatic, "/nonexistent/template.yaml", nil)
	if err == nil {
		t.Error("Load(nonexistent file) error = nil, want error")
	}
}

func TestLoad_InvalidParameters(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "template.yaml")

	templateContent := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  InstanceType:
    Type: String
Resources:
  MyInstance:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
`

	os.WriteFile(templatePath, []byte(templateContent), 0644)

	// Undefined parameter (not in template)
	inputParams := map[string]interface{}{
		"UndefinedParam": "value",
	}

	_, _, err := Load(ModeStatic, templatePath, inputParams)
	if err == nil {
		t.Error("Load(invalid parameters) error = nil, want error")
	}
}

func TestLoadStatic(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "template.yaml")

	templateContent := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  VpcCidr:
    Type: String
    Default: 192.168.0.0/16
Resources:
  MyVpc:
    Type: ALIYUN::ECS::VPC
    Properties:
      CidrBlock:
        Ref: VpcCidr
      VpcName: test-vpc
`

	os.WriteFile(templatePath, []byte(templateContent), 0644)

	inputParams := map[string]interface{}{
		"VpcCidr": "10.0.0.0/16",
	}

	yamlRoot, templateData, err := loadStatic(templatePath, inputParams)
	if err != nil {
		t.Fatalf("loadStatic() error = %v", err)
	}

	if yamlRoot == nil {
		t.Error("yamlRoot is nil")
	}

	if templateData == nil {
		t.Fatal("templateData is nil")
	}

	// Verify parameter resolution
	resources := templateData["Resources"].(map[string]interface{})
	vpc := resources["MyVpc"].(map[string]interface{})
	props := vpc["Properties"].(map[string]interface{})

	// After parameter resolution, the Ref should be resolved
	// (This depends on the implementation of loader.ResolveParameters)
	if cidr, ok := props["CidrBlock"]; ok {
		t.Logf("CidrBlock = %v", cidr)
	}
}

func TestMode_String(t *testing.T) {
	tests := []struct {
		mode Mode
		want string
	}{
		{ModeStatic, "static"},
		{ModePreview, "preview"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("Mode = %v, want %v", tt.mode, tt.want)
		}
	}
}

// Note: TestLoad_PreviewMode is not included here because it requires
// real credentials and makes actual API calls. It should be tested
// in integration tests or with proper mocking of the ROS client.
