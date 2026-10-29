package terraform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadContentEvaluatesVariablesAndNestedBlocks(t *testing.T) {
	content := `variable "name" { default = "default" }
variable "count" { default = 1 }
variable "enabled" { default = false }
variable "ratio" { default = 1.5 }
locals { label = "${var.name}-suffix" }
resource "example_service" "one" {
  name = local.label
  count_value = var.count
  enabled = var.enabled
  ratio = var.ratio
  unresolved = unknown_reference.value
  item { value = "first" }
  item { value = "second" }
}
data "example_lookup" "data" { name = var.name }
output "result" { value = local.label }
`
	data, err := LoadContent("", content, map[string]interface{}{"name": "custom", "count": 3, "enabled": true, "ratio": 2.5})
	if err != nil {
		t.Fatal(err)
	}
	resources := data["resources"].(map[string]interface{})
	one := resources["example_service"].(map[string]interface{})["one"].(map[string]interface{})
	if one["name"] != "custom-suffix" || one["count_value"] != float64(3) || one["enabled"] != true || one["ratio"] != 2.5 || one["unresolved"] != UnknownValue {
		t.Fatalf("resource values: %+v", one)
	}
	nested, ok := one["item"].([]interface{})
	if !ok || len(nested) != 2 {
		t.Fatalf("nested blocks: %#v", one["item"])
	}
	if meta := one["__meta__"].(map[string]interface{}); meta["filename"] != "main.tf" {
		t.Fatalf("metadata: %v", meta)
	}
	if _, err := LoadContent("bad.tf", "resource {", nil); err == nil {
		t.Fatal("invalid HCL accepted")
	}
}

func TestTerraformPathDetection(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "main.tf")
	if err := os.WriteFile(nested, []byte("resource \"example\" \"one\" {}"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsTerraformFile("MAIN.TF") || IsTerraformFile("template.yaml") || !IsTerraformDir(root) || IsTerraformDir(nested) {
		t.Fatal("terraform path detection")
	}
	if _, err := Load(filepath.Join(root, "missing.tf"), nil); err == nil {
		t.Fatal("missing path accepted")
	}
	invalid := filepath.Join(root, "other.txt")
	if err := os.WriteFile(invalid, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(invalid, nil); err == nil {
		t.Fatal("non Terraform file accepted")
	}
}

func TestLoadContentPreservesStructuredAndUnknownValues(t *testing.T) {
	content := `variable "unset" {}
locals {
  fallback = missing.value
  labels = { team = "platform", priority = 2 }
}
resource "example_service" "one" {
  enabled = false
  names = ["first", "second"]
  labels = local.labels
  nil_value = null
  missing = var.unset
  expression = local.fallback
  dynamic "item" {
    for_each = []
    content { name = "ignored" }
  }
}
`
	data, err := LoadContent("example.tf", content, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := data["resources"].(map[string]interface{})["example_service"].(map[string]interface{})["one"].(map[string]interface{})
	names, ok := r["names"].([]interface{})
	if !ok || len(names) != 2 || names[0] != "first" || names[1] != "second" {
		t.Fatalf("list: %#v", r["names"])
	}
	labels, ok := r["labels"].(map[string]interface{})
	if !ok || labels["team"] != "platform" || labels["priority"] != float64(2) {
		t.Fatalf("object: %#v", r["labels"])
	}
	if r["nil_value"] != nil || r["missing"] != UnknownValue || r["expression"] != UnknownValue {
		t.Fatalf("unknown/null: %#v", r)
	}
	if _, ok := r["dynamic"]; ok {
		t.Fatalf("dynamic block is not statically evaluated: %#v", r)
	}
}
