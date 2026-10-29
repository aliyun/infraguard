package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyMetadataValidationErrors(t *testing.T) {
	for _, tc := range []struct {
		name, kind, meta string
		want             []string
	}{
		{"pack non-object", "pack", `[]`, []string{ErrCodePackMissingMeta}},
		{"pack null", "pack", `null`, []string{ErrCodePackMissingMeta}},
		{"rule non-object", "rule", `[]`, []string{ErrCodeRuleMissingMeta}},
		{"rule null", "rule", `null`, []string{ErrCodeRuleMissingMeta}},
		{"pack missing", "pack", `{}`, []string{ErrCodePackMissingID, ErrCodePackMissingName, ErrCodePackMissingRules}},
		{"pack empty fields", "pack", `{"id":"","name":{},"rules":[]}`, []string{ErrCodePackMissingID, ErrCodePackMissingName, ErrCodePackMissingRules}},
		{"pack invalid types", "pack", `{"id":3,"name":3,"rules":"bad","description":false}`, []string{ErrCodePackMissingID, ErrCodePackMissingName + "_TYPE", ErrCodePackInvalidFieldType, ErrCodeRuleInvalidFieldType}},
		{"rule missing", "rule", `{}`, []string{ErrCodeRuleMissingID, ErrCodeRuleMissingName, ErrCodeRuleMissingReason, ErrCodeRuleMissingSeverity}},
		{"rule invalid types", "rule", `{"id":3,"name":3,"reason":false,"severity":3,"description":2,"recommendation":false}`, []string{ErrCodeRuleMissingID, ErrCodeRuleMissingName + "_TYPE", ErrCodeRuleMissingReason + "_TYPE", ErrCodeRuleInvalidFieldType, ErrCodeRuleInvalidFieldType, ErrCodeRuleInvalidFieldType}},
		{"rule invalid severity", "rule", `{"id":"test","name":"Name","reason":"Reason","severity":"urgent"}`, []string{ErrCodeRuleInvalidSeverity}},
		{"valid pack", "pack", `{"id":"test","name":{"en":"Name"},"rules":["rule:test"]}`, nil},
		{"valid rule", "rule", `{"id":"test","name":"Name","reason":"Reason","severity":"high","description":"d"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := fmt.Sprintf("package test\nimport rego.v1\n%s_meta := %s\n", tc.kind, tc.meta)
			var got []*ValidationError
			if tc.kind == "rule" {
				got = validateRuleMeta(content, "test.rego", "test", nil)
			} else {
				got = validatePackMeta(content, "test.rego", "test", nil)
			}
			counts := map[string]int{}
			for _, e := range got {
				counts[e.ErrorCode]++
			}
			for _, code := range tc.want {
				counts[code]--
				if counts[code] < 0 {
					t.Errorf("missing %s in %+v", code, got)
				}
			}
			for code, n := range counts {
				if n != 0 {
					t.Errorf("unexpected %s x%d: %+v", code, n, got)
				}
			}
		})
	}
}

func TestValidatePoliciesDoesNotSkipMalformedPolicy(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"rule.rego":   "package infraguard.rules.aliyun.sample\n???\n",
		"pack.rego":   "package infraguard.packs.aliyun.sample\n???\n",
		"helper.rego": "package other.helper\nvalue := true\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"rule.rego", "pack.rego"} {
		summary, err := ValidatePolicies(filepath.Join(dir, name))
		if err != nil || summary.TotalFiles != 1 || summary.FailedFiles != 1 || len(summary.Results) != 1 || len(summary.Results[0].Errors) != 1 || summary.Results[0].Errors[0].ErrorCode != ErrCodeSyntaxError {
			t.Fatalf("malformed %s: %+v %v", name, summary, err)
		}
	}
	summary, err := ValidatePolicies(dir)
	if err != nil || summary.TotalFiles != 2 || summary.FailedFiles != 2 || summary.SkippedFiles != 1 {
		t.Fatalf("directory summary: %+v %v", summary, err)
	}
}

func TestDenyResultValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		count      int
		code       string
	}{
		{"missing deny", `other := true`, 1, ErrCodeRuleMissingDeny},
		{"empty result", `deny contains {} if { true }`, 3, ErrCodeRuleInvalidDenyFormat},
		{"missing meta details", `deny contains {"id":"rule", "resource_id":"x", "meta":{}} if { true }`, 2, ErrCodeRuleInvalidDenyFormat},
		{"valid result", `deny contains {"id":"rule", "resource_id":"x", "meta":{"severity":"high", "reason":"r"}} if { true }`, 0, ""},
		{"no violations", `deny contains {"id":"rule"} if { false }`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := "package test\nimport rego.v1\n" + tc.body
			got := validateDenyRule(content, "test.rego", "test", nil)
			if len(got) != tc.count {
				t.Fatalf("diagnostics: %+v", got)
			}
			for _, e := range got {
				if e.ErrorCode != tc.code {
					t.Errorf("unexpected code: %+v", e)
				}
			}
		})
	}
}

func TestValidationRejectsBrokenOrMissingDefinitions(t *testing.T) {
	for _, tc := range []struct {
		name, content, code string
		validate            func(string, string, string, []RegoModule) []*ValidationError
	}{
		{"rule syntax", "package test\nrule_meta := ???", ErrCodeRuleMissingMeta, validateRuleMeta},
		{"rule undefined", "package test\nother := true", ErrCodeRuleMissingMeta, validateRuleMeta},
		{"pack syntax", "package test\npack_meta := ???", ErrCodePackMissingMeta, validatePackMeta},
		{"pack undefined", "package test\nother := true", ErrCodePackMissingMeta, validatePackMeta},
		{"deny syntax", "package test\ndeny := ???", ErrCodeRuleMissingDeny, validateDenyRule},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.validate(tc.content, "test.rego", "test", nil)
			if len(got) != 1 || got[0].ErrorCode != tc.code || got[0].FilePath != "test.rego" {
				t.Fatalf("diagnostics: %+v", got)
			}
		})
	}
}

func TestDenyValidationReportsConflictingResults(t *testing.T) {
	content := `package test
import rego.v1
deny := {"first"} if { true }
deny := {"second"} if { true }
`
	got := validateDenyRule(content, "conflict.rego", "test", nil)
	if len(got) != 1 || got[0].ErrorCode != ErrCodeRuleMissingDeny || got[0].Message == "" {
		t.Fatalf("conflicting deny results should produce an evaluation diagnostic: %+v", got)
	}
}
