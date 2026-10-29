package ros

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadLocalTemplateIntrinsicTagsAndErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := write("template.yaml", `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  Name:
    Type: String
Resources:
  Example:
    Type: ALIYUN::TEST::Thing
    Properties:
      Name: !Ref Name
      Joined: !Join [",", [a, b]]
      Metadata: !Sub {Key: value}
`)
	root, data, err := LoadLocalTemplate(path)
	if err != nil || root == nil {
		t.Fatalf("load YAML: %v", err)
	}
	props := data["Resources"].(map[string]interface{})["Example"].(map[string]interface{})["Properties"].(map[string]interface{})
	if !reflect.DeepEqual(props["Name"], map[string]interface{}{"Ref": "Name"}) || !reflect.DeepEqual(props["Joined"], map[string]interface{}{"Fn::Join": []interface{}{",", []interface{}{"a", "b"}}}) || !reflect.DeepEqual(props["Metadata"], map[string]interface{}{"Fn::Sub": map[string]interface{}{"Key": "value"}}) {
		t.Fatalf("intrinsics: %#v", props)
	}
	if _, data, err := LoadLocalTemplate(write("empty.yaml", "")); err != nil || len(data) != 0 {
		t.Fatalf("empty template: %#v %v", data, err)
	}
	if _, _, err := LoadLocalTemplate(write("array.yaml", "- item\n")); err == nil {
		t.Fatal("non-map YAML accepted")
	}
	if _, _, err := LoadLocalTemplate(write("invalid.yaml", "x: [\n")); err == nil {
		t.Fatal("invalid YAML accepted")
	}
	if _, _, err := LoadLocalTemplate(write("invalid.json", "{\n")); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, data, err := LoadLocalTemplate(write("template.json", `{"Resources":{}}`)); err != nil || data["Resources"] == nil {
		t.Fatalf("JSON template: %#v %v", data, err)
	}
}

func TestValidateROSTemplateResourceShape(t *testing.T) {
	for _, tc := range []struct {
		name      string
		data      map[string]interface{}
		wantField string
	}{
		{"missing version", map[string]interface{}{}, "ROSTemplateFormatVersion"},
		{"non-string version", map[string]interface{}{"ROSTemplateFormatVersion": 1}, "ROSTemplateFormatVersion"},
		{"unsupported version", map[string]interface{}{"ROSTemplateFormatVersion": "bad"}, "ROSTemplateFormatVersion"},
		{"missing resources", map[string]interface{}{"ROSTemplateFormatVersion": "2015-09-01"}, "Resources"},
		{"invalid resources", map[string]interface{}{"ROSTemplateFormatVersion": "2015-09-01", "Resources": []interface{}{}}, "Resources"},
		{"invalid resource", map[string]interface{}{"ROSTemplateFormatVersion": "2015-09-01", "Resources": map[string]interface{}{"Item": "bad"}}, "Resources.Item"},
		{"missing type", map[string]interface{}{"ROSTemplateFormatVersion": "2015-09-01", "Resources": map[string]interface{}{"Item": map[string]interface{}{}}}, "Resources.Item.Type"},
		{"invalid type", map[string]interface{}{"ROSTemplateFormatVersion": "2015-09-01", "Resources": map[string]interface{}{"Item": map[string]interface{}{"Type": 3}}}, "Resources.Item.Type"},
		{"invalid properties", map[string]interface{}{"ROSTemplateFormatVersion": "2015-09-01", "Resources": map[string]interface{}{"Item": map[string]interface{}{"Type": "X", "Properties": "bad"}}}, "Resources.Item.Properties"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateROSTemplate(tc.data)
			v, ok := err.(*ROSTemplateValidationError)
			if !ok || v.Field != tc.wantField {
				t.Fatalf("error: %#v", err)
			}
		})
	}
}
