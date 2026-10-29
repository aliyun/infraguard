package mapper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	"gopkg.in/yaml.v3"
)

func TestMapViolationToRealSourceContext(t *testing.T) {
	content := "Resources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\n    Properties:\n      Ports:\n        - 80\n        - 22\n      Name: example\n"
	path := filepath.Join(t.TempDir(), "template.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		t.Fatal(err)
	}
	input := []models.OPAViolation{{ID: "rule:aliyun:port", ResourceID: "Instance", ViolationPath: []interface{}{"Properties", "Ports", 1}, Meta: models.ViolationMeta{Severity: "high", Reason: map[string]interface{}{"en": "open port", "zh": "开放端口"}, Recommendation: "close port"}}}
	got := MapViolationsWithLang(input, &root, path, "zh-CN")
	if len(got) != 1 || got[0].Line != 7 || got[0].Snippet != "- 22" || got[0].Reason != "开放端口" {
		t.Fatalf("mapped violation: %+v", got)
	}
	highlighted := 0
	for _, line := range got[0].SnippetLines {
		if line.Highlight {
			highlighted++
			if line.LineNum != 7 {
				t.Errorf("highlighted line: %+v", line)
			}
		}
	}
	if highlighted != 1 || len(got[0].SnippetLines) != 4 {
		t.Fatalf("context: %+v", got[0].SnippetLines)
	}
	missing := MapViolations(input, &root, filepath.Join(t.TempDir(), "missing.yaml"))
	if len(missing) != 1 || missing[0].Line != 7 || missing[0].Snippet != "" {
		t.Fatalf("missing source file: %+v", missing)
	}
}
