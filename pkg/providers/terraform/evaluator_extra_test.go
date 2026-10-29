package terraform

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	"testing"
)

func TestEvaluatorHandlesIncompleteBlocksAndRepeatedNestedBlocks(t *testing.T) {
	source := `resource "missing" {}
data "missing" {}
output {}
resource "example" "test" {
  rule { value = "first" }
  rule { value = "second" }
  rule { value = "third" }
}`
	file, diags := hclsyntax.ParseConfig([]byte(source), "main.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	jsonFile, diags := hcljson.Parse([]byte(`{}`), "ignored.tf.json")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	parsed := &ParsedConfig{Files: map[string]*hcl.File{"main.tf": file, "ignored.tf.json": jsonFile}}
	got, err := evaluate(parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, ok := got.Resources["example"]["test"]["rule"].([]interface{})
	if !ok || len(rules) != 3 || len(got.DataSources) != 0 || len(got.Outputs) != 0 {
		t.Fatalf("evaluated configuration: %+v", got)
	}
}

func TestEvaluatorRejectsInvalidVariableDefaultAndHandlesUnknownValues(t *testing.T) {
	file, diags := hclsyntax.ParseConfig([]byte("variable \"bad\" {\n default = var.other\n}\n"), "invalid.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if _, err := evaluate(&ParsedConfig{Files: map[string]*hcl.File{"invalid.tf": file}}, nil); err == nil {
		t.Fatal("invalid variable default accepted")
	}
	if got := ctyToGo(cty.UnknownVal(cty.String)); got != UnknownValue {
		t.Fatalf("unknown=%v", got)
	}
	if !goToCty(nil).IsNull() || goToCty([]int{1, 2}).AsString() != "[1 2]" {
		t.Fatal("input conversion")
	}
}
