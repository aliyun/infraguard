package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
)

func TestCatalogFilters(t *testing.T) {
	rule := &models.Rule{ID: "rule:aliyun:sample", Name: models.I18nString{"en": "Sample Name"}, Severity: "High", IaCTypes: []string{"ros", "terraform"}, ResourceTypes: []string{"ALIYUN::ECS::Instance", "alicloud_ecs_instance", "alicloud_oss_bucket"}}
	if got := servicesFor(rule.ResourceTypes); !reflect.DeepEqual(got, []string{"ECS", "OSS"}) {
		t.Fatalf("services: %v", got)
	}
	if got := splitCSV(" ecs, , oss ", true); !reflect.DeepEqual(got, []string{"ECS", "OSS"}) {
		t.Fatalf("CSV: %v", got)
	}
	if splitCSV("  ", false) != nil {
		t.Fatal("empty CSV should be nil")
	}
	for _, tc := range []struct {
		severity, iac   string
		services, types []string
		want            bool
	}{
		{"high", "ros", []string{"ECS"}, []string{"ALIYUN::ECS::Instance"}, true},
		{"low", "ros", nil, nil, false}, {"high", "other", nil, nil, false},
		{"high", "ros", []string{"RDS"}, nil, false}, {"high", "ros", nil, []string{"other"}, false},
	} {
		if got := ruleMatchesFilters(rule, tc.severity, tc.iac, tc.services, tc.types); got != tc.want {
			t.Errorf("filters %+v got %v", tc, got)
		}
	}
	for _, q := range []string{"sample", "name", "alicloud_oss"} {
		if !ruleMatchesQuery(rule, q) {
			t.Errorf("query %q did not match", q)
		}
	}
	if ruleMatchesQuery(rule, "absent") {
		t.Fatal("unexpected query match")
	}
	pack := &models.Pack{ID: "pack:aliyun:test", Name: models.I18nString{"en": "Example Pack"}}
	if !packMatchesQuery(pack, "test") || !packMatchesQuery(pack, "example") || packMatchesQuery(pack, "absent") {
		t.Fatal("pack query mismatch")
	}
}

func TestPolicyEndpoints(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	rego := "package infraguard.rules.test.sample\n"
	rule := &models.Rule{ID: "rule:aliyun:sample", Name: models.I18nString{"en": "Sample"}, Severity: "high", IaCTypes: []string{"ros"}, ResourceTypes: []string{"ALIYUN::ECS::Instance"}, FilePath: "sample.rego", Content: rego}
	pack := &models.Pack{ID: "pack:aliyun:sample", RuleIDs: []string{rule.ID}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule}, PackList: []*models.Pack{pack}}
	s := New(Options{Host: "127.0.0.1"})
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/api/policies", 200}, {"/api/policies?type=rule&severity=high&service=ecs&q=sample", 200},
		{"/api/policies?type=pack&iac=ros", 200}, {"/api/policies?resource_type=unknown", 200},
		{"/api/policies/sample", 200}, {"/api/policies/pack:aliyun:sample", 200},
		{"/api/policies/missing", 404}, {"/api/policies/pack:aliyun:missing", 404}, {"/api/coverage", 200},
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.status {
			t.Errorf("%s: status %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		if tc.path == "/api/policies" {
			var got struct {
				Rules []ruleSummary `json:"rules"`
				Packs []packSummary `json:"packs"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Rules) != 1 || len(got.Packs) != 1 || got.Rules[0].ID != rule.ID {
				t.Errorf("catalog: %s (%v)", rec.Body.String(), err)
			}
		}
		if tc.path == "/api/coverage" {
			var got coverage
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.TotalRules != 1 || got.TotalPacks != 1 || got.BySeverity["high"] != 1 {
				t.Errorf("coverage: %s (%v)", rec.Body.String(), err)
			}
		}
	}
	for _, tc := range []struct {
		path, body string
		status     int
	}{
		{"/api/scan", `{"content":"ROSTemplateFormatVersion: '2015-09-01'\nResources: {}","policies":["missing"]}`, 200},
		{"/api/scan", `{"content":"ROSTemplateFormatVersion: '2015-09-01'\nResources: {}","policies":["sample"]}`, 200},
		{"/api/scan", `{"content":"[invalid","policies":["pack:aliyun:sample"]}`, 400},
		{"/api/rule/eval", `{"rego":"package infraguard.rules.test.sample\n","content":"ROSTemplateFormatVersion: '2015-09-01'\nResources: {}"}`, 200},
		{"/api/rule/test", `{"rego":"package infraguard.rules.test.sample\n","compliant":"ROSTemplateFormatVersion: '2015-09-01'\nResources: {}","violation":""}`, 200},
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
		if rec.Code != tc.status {
			t.Errorf("%s: status %d: %s", tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestScanHelpers(t *testing.T) {
	for _, tc := range []struct{ explicit, name, content, want string }{
		{"ROS", "main.tf", "", "ros"}, {"", "MAIN.TF", "", "terraform"},
		{"", "", "resource \"x\" \"y\" {}", "terraform"}, {"", "", "ROSTemplateFormatVersion: '2015'", "ros"}, {"", "", "other", "ros"},
	} {
		if got := detectIaC(tc.explicit, tc.name, tc.content); got != tc.want {
			t.Errorf("detect %+v: %q", tc, got)
		}
	}
	if shortID("rule:aliyun:abc") != "abc" || shortID("other") != "other" || shortID("pack:short") != "pack:short" {
		t.Fatal("short ID mismatch")
	}
	summary := summarize([]models.RichViolation{{Severity: "HIGH"}, {Severity: "low"}})
	if summary.TotalViolations != 2 || summary.FilesWithViolations != 1 || summary.SeverityCounts["high"] != 1 || summary.SeverityCounts["low"] != 1 {
		t.Fatalf("summary: %+v", summary)
	}
	if got := emptySummary(); got.FilesScanned != 1 || got.TotalViolations != 0 {
		t.Fatalf("empty summary: %+v", got)
	}
}

func TestScanContent(t *testing.T) {
	opts := &engine.EvalOptions{Modules: map[string]string{"test.rego": "package infraguard.rules.test.empty\n"}}
	for _, tc := range []struct{ iac, content string }{{"ros", "ROSTemplateFormatVersion: '2015-09-01'\nResources: {}\n"}, {"terraform", "resource \"alicloud_vpc\" \"example\" {}"}} {
		if _, err := scanContent(tc.iac, tc.content, nil, opts, "en"); err != nil {
			t.Errorf("%s valid content: %v", tc.iac, err)
		}
	}
	if _, err := scanContent("ros", "[invalid", nil, opts, "en"); err == nil {
		t.Fatal("expected malformed ROS template to fail")
	}
	if _, err := scanContent("terraform", "resource {", nil, opts, "en"); err == nil {
		t.Fatal("expected malformed Terraform to fail")
	}
}

func TestRuleEndpointsRejectInvalidRequests(t *testing.T) {
	s := New(Options{Host: "127.0.0.1"})
	for _, tc := range []struct{ path, body string }{
		{"/api/scan", "{"}, {"/api/scan", `{}`},
		{"/api/rule/eval", "{"}, {"/api/rule/eval", `{}`},
		{"/api/rule/test", "{"}, {"/api/rule/test", `{}`},
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s: status %d", tc.path, tc.body, rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
			t.Errorf("%s: response %s", tc.path, rec.Body.String())
		}
	}
}

func TestPolicyCatalogFiltersAndCoverageAggregation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	rules := []*models.Rule{
		{ID: "rule:aliyun:alpha", Name: models.I18nString{"en": "Compute"}, Severity: "high", IaCTypes: []string{"ros", "terraform"}, ResourceTypes: []string{"ALIYUN::ECS::Instance", "alicloud_ecs_instance"}},
		{ID: "rule:aliyun:beta", Name: models.I18nString{"en": "Storage"}, Severity: "medium", IaCTypes: []string{"terraform"}, ResourceTypes: []string{"alicloud_oss_bucket"}},
		{ID: "rule:aliyun:gamma", Name: models.I18nString{"en": "Other"}, Severity: "low", IaCTypes: []string{"ros"}, ResourceTypes: []string{"ALIYUN::RDS::DBInstance"}},
	}
	packs := []*models.Pack{{ID: "pack:aliyun:compute", RuleIDs: []string{rules[0].ID}}, {ID: "pack:aliyun:storage", RuleIDs: []string{rules[1].ID, rules[2].ID}}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: rules, PackList: packs}
	s := New(Options{Host: "127.0.0.1"})
	for _, tc := range []struct{ query, ruleID, packID string }{
		{"?severity=high&service=ecs", rules[0].ID, packs[0].ID},
		{"?iac=terraform&resource_type=alicloud_oss_bucket", rules[1].ID, packs[1].ID},
		{"?service=absent,%20rds", rules[2].ID, packs[1].ID},
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/policies"+tc.query, nil))
		var got struct {
			Rules []ruleSummary `json:"rules"`
			Packs []packSummary `json:"packs"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 || len(got.Rules) != 1 || len(got.Packs) != 1 || got.Rules[0].ID != tc.ruleID || got.Packs[0].ID != tc.packID {
			t.Errorf("filter %q: status=%d body=%s err=%v", tc.query, rec.Code, rec.Body, err)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/coverage", nil))
	var got coverage
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TotalRules != 3 || got.TotalPacks != 2 || got.ByIaC["both"] != 1 || got.ByIaC["terraform"] != 1 || got.ByIaC["ros"] != 1 || got.BySeverity["high"] != 1 || len(got.ByService) != 3 || got.ByService[0].Count != 1 || len(got.ByFramework) != 2 || got.ByFramework[0].ID != packs[1].ID {
		t.Fatalf("coverage: %+v", got)
	}
}

func TestRuleStudioEvaluatesFixturesAndReturnsViolations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	rego := `package infraguard.rules.test.public
import rego.v1
deny contains result if {
 input.Resources.Thing.Properties.Public == true
 result := {"id":"public", "resource_id":"Thing", "violation_path":["Resources","Thing","Properties","Public"], "meta":{"severity":"high", "reason":"public access"}}
}`
	fixture := func(public string) string {
		return "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n    Properties:\n      Public: " + public + "\n"
	}
	encode := func(v interface{}) *strings.Reader {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return strings.NewReader(string(b))
	}
	s := New(Options{Host: "127.0.0.1"})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/rule/test", encode(ruleTestRequest{Rego: rego, Compliant: fixture("false"), Violation: fixture("true")})))
	var result struct {
		Pass      bool        `json:"pass"`
		Compliant caseOutcome `json:"compliant"`
		Violation caseOutcome `json:"violation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || rec.Code != 200 || !result.Pass || !result.Compliant.Pass || result.Compliant.Violations != 0 || !result.Violation.Pass || result.Violation.Violations != 1 {
		t.Fatalf("test status=%d body=%s error=%v", rec.Code, rec.Body, err)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/rule/eval", encode(ruleEvalRequest{Rego: rego, Content: fixture("true")})))
	var evaluation struct {
		IaC        string                 `json:"iac"`
		Violations []models.RichViolation `json:"violations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &evaluation); err != nil || rec.Code != 200 || evaluation.IaC != "ros" || len(evaluation.Violations) != 1 || evaluation.Violations[0].File != "template" {
		t.Fatalf("eval status=%d body=%s error=%v", rec.Code, rec.Body, err)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/rule/eval", encode(ruleEvalRequest{Rego: rego, Content: "[broken"})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid template status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestResolveEvalOptionsSelectsIaCImplementations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	rule := &models.Rule{ID: "rule:aliyun:sample", IaCTypes: []string{"ros", "terraform"}, Content: "fallback", FilePath: "fallback.rego", Implementations: map[string]*models.RuleImpl{"ros": {FilePath: "ros.rego", Content: "ros module"}, "terraform": {FilePath: "tf.rego", Content: "terraform module"}}}
	other := &models.Rule{ID: "rule:aliyun:other", IaCTypes: []string{"terraform"}, FilePath: "other.rego", Content: "other module"}
	pack := &models.Pack{ID: "pack:aliyun:sample", RuleIDs: []string{rule.ID, other.ID, "missing"}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule, other}, PackList: []*models.Pack{pack}, LibModules: map[string]string{"helper.rego": "helper"}}
	loader, err := policy.LoadWithFallback()
	if err != nil {
		t.Fatal(err)
	}
	for _, specs := range [][]string{nil, {"sample"}, {"rule:aliyun:sample"}, {pack.ID}} {
		opts := resolveEvalOptions(loader, specs, "ros")
		if len(opts.Modules) != 1 || opts.Modules["ros.rego"] != "ros module" || opts.IDMapping["sample"] != rule.ID || opts.LibModules["helper.rego"] != "helper" || len(opts.RuleIDs) != 1 {
			t.Fatalf("specs=%v opts=%+v", specs, opts)
		}
	}
	opts := resolveEvalOptions(loader, []string{pack.ID}, "terraform")
	if len(opts.Modules) != 2 || opts.Modules["tf.rego"] != "terraform module" || opts.Modules["other.rego"] != "other module" {
		t.Fatalf("terraform opts=%+v", opts)
	}
	opts = resolveEvalOptions(loader, []string{"missing", "pack:aliyun:missing"}, "ros")
	if len(opts.Modules) != 0 {
		t.Fatalf("unknown opts=%+v", opts)
	}
}

func TestEndpointsReportMissingPolicyCatalog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "missing-user"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "missing-workspace"))
	old := policy.EmbeddedIndex
	policy.EmbeddedIndex = nil
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	s := New(Options{Host: "127.0.0.1"})
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/policies", ""}, {http.MethodGet, "/api/policies/sample", ""}, {http.MethodGet, "/api/coverage", ""},
		{http.MethodPost, "/api/scan", `{"content":"Resources: {}"}`},
		{http.MethodPost, "/api/rule/eval", `{"rego":"package test", "content":"Resources: {}"}`},
		{http.MethodPost, "/api/rule/test", `{"rego":"package test"}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			var body map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("error body=%s err=%v", rec.Body, err)
			}
			if msg, ok := body["error"].(string); !ok || msg == "" {
				t.Fatalf("missing error message: %s", rec.Body)
			}
		})
	}
}
