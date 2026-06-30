package policies_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var policyDocLanguages = []string{"en", "zh", "es", "fr", "de", "ja", "pt"}

func TestAliyunROSRulesHaveDocumentationLocales(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("aliyun", "rules", "ros", "*.rego"))
	if err != nil {
		t.Fatalf("glob ROS rules: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected ROS rule files")
	}

	fields := []string{"name", "description", "reason", "recommendation"}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(content)
		for _, field := range fields {
			body, ok := metadataObjectBody(text, field)
			if !ok {
				t.Errorf("%s missing rule_meta.%s documentation", file, field)
				continue
			}
			for _, lang := range policyDocLanguages {
				if !strings.Contains(body, `"`+lang+`"`) {
					t.Errorf("%s missing rule_meta.%s.%s documentation", file, field, lang)
				}
			}
		}
	}
}

func metadataObjectBody(content, field string) (string, bool) {
	pattern := regexp.MustCompile(`(?s)"` + regexp.QuoteMeta(field) + `"\s*:\s*\{(.*?)\n\s*\}`)
	matches := pattern.FindStringSubmatch(content)
	if len(matches) != 2 {
		return "", false
	}
	return matches[1], true
}
