package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/providers/ros"
	"github.com/aliyun/infraguard/pkg/waiver"
	"gopkg.in/yaml.v3"
)

func TestScanErrorOutputFormats(t *testing.T) {
	apiError := &ros.FormattedAPIError{StatusCode: 403, Code: "Denied", Message: "not allowed", RequestID: "request-123"}
	for _, terminal := range []bool{false, true} {
		var output bytes.Buffer
		writeScanError(&output, "file.yaml", fmt.Errorf("wrapped: %w", apiError), i18n.Msg(), terminal)
		writeScanError(&output, "other.yaml", errors.New("plain failure"), i18n.Msg(), terminal)
		for _, want := range []string{"file.yaml", "403", "Denied", "not allowed", "request-123", "other.yaml", "plain failure"} {
			if !strings.Contains(output.String(), want) {
				t.Errorf("terminal=%v output missing %q: %q", terminal, want, output.String())
			}
		}
	}
}

func TestScanExitCodesForViolations(t *testing.T) {
	for _, tc := range []struct {
		severity string
		want     int
	}{{"high", 2}, {"low", 1}, {"mixed", 2}} {
		t.Run(tc.severity, func(t *testing.T) {
			root := t.TempDir()
			severity := tc.severity
			if severity == "mixed" {
				severity = "high"
			}
			rego := `package infraguard.rules.test.sample
import rego.v1
deny contains result if {
 input.Resources.Thing.Properties.Public == true
 result := {"id":"sample", "resource_id":"Thing", "violation_path":["Properties","Public"], "meta":{"severity":"` + severity + `", "reason":"public access"}}
}`
			if tc.severity == "mixed" {
				rego += `
deny contains result if {
 input.Resources.Thing.Properties.Public == true
 result := {"id":"sample-low", "resource_id":"Thing", "violation_path":["Properties","Public"], "meta":{"severity":"low", "reason":"secondary"}}
}`
			}
			if err := os.WriteFile(filepath.Join(root, "rule.rego"), []byte(rego), 0600); err != nil {
				t.Fatal(err)
			}
			content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n    Properties:\n      Public: true\n"
			if err := os.WriteFile(filepath.Join(root, "template.yaml"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestScanExitHelper$")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "INFRAGUARD_SCAN_EXIT_TEST=1")
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != tc.want || !strings.Contains(string(output), "public access") {
				t.Fatalf("scan exit: output=%q error=%v", output, err)
			}
			if tc.severity == "mixed" {
				start := strings.IndexByte(string(output), '{')
				if start < 0 {
					t.Fatalf("missing JSON report: %q", output)
				}
				var report models.Report
				if err := json.NewDecoder(strings.NewReader(string(output[start:]))).Decode(&report); err != nil || len(report.Results) != 1 || len(report.Results[0].Violations) != 2 || report.Results[0].Violations[0].Severity != "high" {
					t.Fatalf("severity ordering: %+v %v", report, err)
				}
			}
		})
	}
}

func TestScanExitHelper(t *testing.T) {
	mode := os.Getenv("INFRAGUARD_SCAN_EXIT_TEST")
	if (mode != "1" && mode != "waived" && mode != "inline") || flag.Lookup("test.run").Value.String() != "^TestScanExitHelper$" {
		return
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	scanPolicies, scanFormat, scanOutput, scanInput = []string{filepath.Join(dir, "rule.rego")}, "json", "", nil
	scanMode, scanSeverities, globalLang, scanNoWaivers = "static", nil, "", true
	input := filepath.Join(dir, "template.yaml")
	if mode == "waived" {
		input = filepath.Join(dir, "main.tf")
		scanWaivers, scanNoWaivers, scanShowWaived = filepath.Join(dir, "waivers.yaml"), false, true
	} else if mode == "inline" {
		scanWaivers, scanNoWaivers, scanShowWaived = "", false, true
	}
	if err := runScan(nil, []string{input}); err != nil {
		t.Fatal(err)
	}
	if mode == "waived" || mode == "inline" {
		return
	}
	t.Fatal("scan returned despite a violation")
}

func TestScanUsesInlineWaiver(t *testing.T) {
	root := t.TempDir()
	rego := `package infraguard.rules.test.sample
import rego.v1
deny contains result if {
 input.Resources.Thing.Properties.Public == true
 result := {"id":"sample", "resource_id":"Thing", "violation_path":["Properties","Public"], "meta":{"severity":"high", "reason":"public access"}}
}`
	if err := os.WriteFile(filepath.Join(root, "rule.rego"), []byte(rego), 0600); err != nil {
		t.Fatal(err)
	}
	content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  # infraguard:ignore=sample reason=\"inline approval\" expires=2099-01-01\n  Thing:\n    Type: ALIYUN::TEST::Thing\n    Properties:\n      Public: true\n"
	if err := os.WriteFile(filepath.Join(root, "template.yaml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waiver.Save(filepath.Join(root, waiver.DefaultRelPath), nil); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestScanExitHelper$")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "INFRAGUARD_SCAN_EXIT_TEST=inline")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inline-waived scan: %v: %s", err, output)
	}
	start := strings.IndexByte(string(output), '{')
	if start < 0 {
		t.Fatalf("missing report: %q", output)
	}
	var report models.Report
	if err := json.NewDecoder(strings.NewReader(string(output[start:]))).Decode(&report); err != nil || report.Summary.WaivedCount != 1 || len(report.Results) != 1 || len(report.Results[0].Violations) != 1 {
		t.Fatalf("inline waiver report: %+v %v", report, err)
	}
	w := report.Results[0].Violations[0].Waiver
	if w == nil || w.Source != "inline" || w.Reason != "inline approval" {
		t.Fatalf("inline waiver: %+v", w)
	}
}

func TestTerraformScanMapsAndWaivesViolation(t *testing.T) {
	root := t.TempDir()
	rego := `package infraguard.rules.test.sample
import rego.v1
deny contains result if {
 input.resources.alicloud_vpc.example.vpc_name == "public"
 result := {"id":"sample", "resource_id":"alicloud_vpc.example", "violation_path":["vpc_name"], "meta":{"severity":"high", "reason":"public access"}}
}`
	if err := os.WriteFile(filepath.Join(root, "rule.rego"), []byte(rego), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource \"alicloud_vpc\" \"example\" {\n  vpc_name = \"public\"\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waiver.Save(filepath.Join(root, "waivers.yaml"), []waiver.Waiver{{Rule: "sample", Resource: "alicloud_vpc.example", Reason: "approved", Expires: "2099-01-01"}}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestScanExitHelper$")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "INFRAGUARD_SCAN_EXIT_TEST=waived")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("waived Terraform scan: %v: %s", err, output)
	}
	start := strings.IndexByte(string(output), '{')
	if start < 0 {
		t.Fatalf("missing report: %q", output)
	}
	var report models.Report
	if err := json.NewDecoder(strings.NewReader(string(output[start:]))).Decode(&report); err != nil || report.Summary.WaivedCount != 1 || len(report.Results) != 1 || len(report.Results[0].Violations) != 1 {
		t.Fatalf("waiver report: %+v %v", report, err)
	}
	violation := report.Results[0].Violations[0]
	if violation.Line != 1 || filepath.Base(violation.File) != "main.tf" || violation.Waiver == nil || violation.Waiver.Reason != "approved" {
		t.Fatalf("mapped violation: %+v", violation)
	}
}

func TestScanReportsWrappedAPIErrors(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = oldStderr; f.Close() })
	apiError := &ros.FormattedAPIError{StatusCode: 403, Code: "Denied", Message: "not allowed", RequestID: "request-123"}
	formatAndPrintError("template.yaml", fmt.Errorf("preview: %w", apiError), i18n.Msg())
	formatAndPrintError("other.yaml", errors.New("invalid template"), i18n.Msg())
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"template.yaml", "403", "Denied", "not allowed", "request-123", "other.yaml", "invalid template"} {
		if !strings.Contains(string(data), value) {
			t.Errorf("missing %q in output %q", value, data)
		}
	}
}

func TestScanSkipsRulesForOtherIaCTypes(t *testing.T) {
	oldIndex := policy.EmbeddedIndex
	oldPolicies, oldFormat, oldOutput, oldInput := scanPolicies, scanFormat, scanOutput, scanInput
	oldMode, oldSeverities, oldLang, oldNoWaivers, oldStdout := scanMode, scanSeverities, globalLang, scanNoWaivers, os.Stdout
	t.Cleanup(func() {
		policy.EmbeddedIndex = oldIndex
		scanPolicies, scanFormat, scanOutput, scanInput = oldPolicies, oldFormat, oldOutput, oldInput
		scanMode, scanSeverities, globalLang, scanNoWaivers, os.Stdout = oldMode, oldSeverities, oldLang, oldNoWaivers, oldStdout
	})
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	rule := &models.Rule{ID: "rule:aliyun:ros-only", IaCTypes: []string{"ros"}, FilePath: "ros-only.rego", Content: "package infraguard.rules.ros_only"}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule}}
	file := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(file, []byte(`resource "alicloud_vpc" "example" {}`), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	os.Stdout = output
	scanPolicies, scanFormat, scanOutput, scanInput = []string{rule.ID}, "json", "", nil
	scanMode, scanSeverities, globalLang, scanNoWaivers = "static", nil, "", true
	if err := runScan(nil, []string{file}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	var report models.Report
	if err := json.Unmarshal(data, &report); err != nil || len(report.Results) != 1 || len(report.Results[0].Violations) != 0 {
		t.Fatalf("report %q: %+v %v", data, report, err)
	}
}

func TestCollectAndLoadTemplates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	rosFile := write("template.yaml", "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\n")
	tf := write("terraform/main.tf", `resource "alicloud_vpc" "example" {}`)
	tf2 := write("terraform/variables.tf", "variable \"name\" {}")
	write("ignored.txt", "ignored")
	files, err := collectTemplates([]string{rosFile, tf, tf2, dir, rosFile})
	if err != nil || len(files) != 2 {
		t.Fatalf("templates %v: %v", files, err)
	}
	if _, err := collectTemplates([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("missing template path accepted")
	}
	root, data, err := loadTemplateWithMode(rosFile, nil, "static")
	if err != nil || root == nil || data == nil {
		t.Fatalf("ROS load: %v", err)
	}
	lines := extractROSResourceLines(root)
	if len(lines) != 1 || lines[0].ID != "Instance" || lines[0].Line != 3 {
		t.Fatalf("ROS resource lines: %+v", lines)
	}
	if _, _, err := loadTemplateWithMode(rosFile, nil, "invalid"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, _, err := loadTemplateWithMode(write("invalid.yaml", "name: x"), nil, "static"); err == nil {
		t.Fatal("non ROS template accepted")
	}
	if root, data, err := loadTemplateWithMode(tf, nil, "static"); err != nil || root != nil || data == nil {
		t.Fatalf("Terraform load: %v", err)
	}
}

func TestBuildScanOptionsFromCatalog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	high := &models.Rule{ID: "rule:aliyun:high-example", Severity: "high", IaCTypes: []string{"ros"}, FilePath: "high.rego", Content: "package example.high"}
	low := &models.Rule{ID: "rule:aliyun:low-example", Severity: "low", IaCTypes: []string{"terraform"}, FilePath: "low.rego", Content: "package example.low"}
	pack := &models.Pack{ID: "pack:aliyun:example", RuleIDs: []string{high.ID, low.ID, "missing"}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{high, low}, PackList: []*models.Pack{pack}, LibModules: map[string]string{"lib.rego": "package example.lib"}}
	for _, pattern := range []string{high.ID, "rule:aliyun:high-*", pack.ID, "pack:aliyun:exam*"} {
		spec, err := parsePolicySpec(pattern)
		if err != nil {
			t.Fatal(err)
		}
		opts, iac, err := buildEvalOptions([]*PolicySpec{spec}, i18n.Msg(), map[string]bool{"high": true})
		if err != nil || len(opts.Modules) != 1 || opts.Modules["high.rego"] != high.Content || iac["high.rego"].ruleID != high.ID || opts.LibModules["lib.rego"] == "" {
			t.Fatalf("pattern %q: %+v %+v %v", pattern, opts, iac, err)
		}
	}
	for _, pattern := range []string{"rule:aliyun:absent", "rule:aliyun:no-*", "pack:aliyun:absent", "pack:aliyun:no-*"} {
		spec, err := parsePolicySpec(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := buildEvalOptions([]*PolicySpec{spec}, i18n.Msg(), nil); err == nil {
			t.Errorf("missing %q accepted", pattern)
		}
	}
	if _, _, err := buildEvalOptions([]*PolicySpec{{Type: "file", Value: "local.rego"}}, i18n.Msg(), map[string]bool{"high": true}); err == nil {
		t.Fatal("severity filter accepted for local policy")
	}
	if _, _, err := buildEvalOptions(nil, i18n.Msg(), map[string]bool{"medium": true}); err != nil {
		t.Fatalf("empty filtered fallback: %v", err)
	}
}

func TestBuildScanOptionsWithoutEmbeddedCatalog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	policyDir := filepath.Join(home, "policies")
	t.Setenv("INFRAGUARD_POLICY_DIR", policyDir)
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "workspace"))
	old := policy.EmbeddedIndex
	policy.EmbeddedIndex = nil
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	if _, _, err := buildEvalOptions(nil, i18n.Msg(), nil); err == nil {
		t.Fatal("missing embedded and local policies accepted")
	}
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(policyDir, "local.rego")
	if err := os.WriteFile(path, []byte("package example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := buildEvalOptions(nil, i18n.Msg(), nil)
	if err != nil || !reflect.DeepEqual(opts.PolicyPaths, []string{policyDir}) {
		t.Fatalf("local policy fallback: %+v %v", opts, err)
	}
	opts, _, err = buildEvalOptions([]*PolicySpec{{Type: "file", Value: path}}, i18n.Msg(), nil)
	if err != nil || !reflect.DeepEqual(opts.PolicyPaths, []string{path}) {
		t.Fatalf("explicit local policy: %+v %v", opts, err)
	}
}

func TestFilterScanModulesAndResourceLines(t *testing.T) {
	opts := &engine.EvalOptions{Modules: map[string]string{"ros.rego": "ros", "tf.rego": "tf", "shared.rego": "shared"}}
	mapping := map[string]*ruleIaCInfo{"ros.rego": {ruleID: "ros-rule", iacTypes: []string{"ros"}}, "tf.rego": {ruleID: "tf-rule", iacTypes: []string{"terraform"}}}
	warned := map[string]bool{}
	got := filterEvalOptsByIaCType(opts, mapping, "ros", warned)
	if !reflect.DeepEqual(got.Modules, map[string]string{"ros.rego": "ros", "shared.rego": "shared"}) || !warned["tf-rule"] || len(opts.Modules) != 3 {
		t.Fatalf("filtered: %+v warnings %+v", got, warned)
	}
	if filterEvalOptsByIaCType(opts, nil, "ros", warned) != opts {
		t.Fatal("empty map should preserve options")
	}
	if got := formatSeverityFilter(map[string]bool{"low": true, "high": true}); got != "high,low" {
		t.Fatalf("severity ordering: %s", got)
	}
	data := map[string]interface{}{"resources": map[string]interface{}{"alicloud_vpc": map[string]interface{}{
		"good":    map[string]interface{}{"__meta__": map[string]interface{}{"filename": "main.tf", "line": float64(4)}},
		"missing": map[string]interface{}{}, "invalid": map[string]interface{}{"__meta__": map[string]interface{}{"filename": "main.tf", "line": 0}},
	}}}
	result := extractTFResourceLines(data, "/project")
	lines := result[filepath.Join("/project", "main.tf")]
	if len(lines) != 1 || lines[0].ID != "alicloud_vpc.good" || lines[0].Line != 4 {
		t.Fatalf("terraform resource lines: %+v", result)
	}
	if len(extractTFResourceLines(map[string]interface{}{}, "/project")) != 0 || len(extractROSResourceLines(nil)) != 0 {
		t.Fatal("unexpected resource lines")
	}
}

func TestApplyScanWaivers(t *testing.T) {
	old := scanWaivers
	t.Cleanup(func() { scanWaivers = old })
	dir := t.TempDir()
	scanWaivers = filepath.Join(dir, "waivers.yaml")
	if err := waiver.Save(scanWaivers, []waiver.Waiver{{Rule: "sample", Resource: "Item", Reason: "approved", Expires: "2099-01-01"}}); err != nil {
		t.Fatal(err)
	}
	results := []models.FileResult{{File: "template.yaml", Violations: []models.RichViolation{{ID: "rule:aliyun:sample", ResourceID: "Item"}}}}
	if err := applyWaivers(results, nil); err != nil || results[0].Violations[0].Waiver == nil || results[0].Violations[0].Waiver.Status != models.WaiverStatusActive {
		t.Fatalf("waiver result %+v: %v", results, err)
	}
	source := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(source, []byte("# infraguard:ignore=sample reason=\"local approval\" expires=2099-01-01\nItem:\n  Type: example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inlineResults := []models.FileResult{{File: source, Violations: []models.RichViolation{{ID: "rule:aliyun:sample", ResourceID: "Item"}}}}
	lines := map[string][]waiver.ResourceLine{source: {{ID: "Item", Line: 2}}, filepath.Join(dir, "missing.yaml"): {{ID: "Missing", Line: 1}}}
	if err := applyWaivers(inlineResults, lines); err != nil || inlineResults[0].Violations[0].Waiver == nil || inlineResults[0].Violations[0].Waiver.Source != "inline" || inlineResults[0].Violations[0].Waiver.Reason != "local approval" {
		t.Fatalf("inline waiver precedence: %+v %v", inlineResults, err)
	}
	if err := os.WriteFile(scanWaivers, []byte("[invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyWaivers(results, nil); err == nil {
		t.Fatal("invalid waiver file accepted")
	}
}

func TestScanCommandEndToEnd(t *testing.T) {
	oldPolicies, oldFormat, oldOutput, oldInput := scanPolicies, scanFormat, scanOutput, scanInput
	oldMode, oldSeverities, oldLang := scanMode, scanSeverities, globalLang
	oldNoWaivers, oldShowWaived, oldFailExpired := scanNoWaivers, scanShowWaived, scanFailOnExpired
	t.Cleanup(func() {
		scanPolicies, scanFormat, scanOutput, scanInput = oldPolicies, oldFormat, oldOutput, oldInput
		scanMode, scanSeverities, globalLang = oldMode, oldSeverities, oldLang
		scanNoWaivers, scanShowWaived, scanFailOnExpired = oldNoWaivers, oldShowWaived, oldFailExpired
	})
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	policyFile := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(policyFile, []byte("package infraguard.rules.test.empty\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rosFile := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(rosFile, []byte("ROSTemplateFormatVersion: '2015-09-01'\nResources: {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	scanPolicies, scanFormat, scanOutput = []string{policyFile}, "html", filepath.Join(dir, "report.html")
	scanInput, scanMode, scanSeverities, globalLang = nil, "static", nil, ""
	scanNoWaivers, scanShowWaived, scanFailOnExpired = true, false, true
	if err := runScan(nil, []string{rosFile}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(scanOutput); err != nil || info.Size() == 0 {
		t.Fatalf("HTML report: %v", err)
	}
	tfFile := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(tfFile, []byte(`resource "alicloud_vpc" "sample" {}`), 0644); err != nil {
		t.Fatal(err)
	}
	scanFormat = "json"
	if err := runScan(nil, []string{tfFile}); err != nil {
		t.Fatalf("Terraform scan: %v", err)
	}
	badFile := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badFile, []byte("not a ROS template"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runScan(nil, []string{badFile}); err == nil {
		t.Fatal("all invalid templates should fail")
	}
	scanFormat = "bad"
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("invalid format accepted")
	}
	scanFormat, scanMode = "json", "bad"
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	scanMode, globalLang = "static", "unsupported"
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("invalid language accepted")
	}
	globalLang = "fr-FR"
	if err := runScan(nil, []string{rosFile}); err != nil {
		t.Fatalf("supported regional language rejected: %v", err)
	}
	globalLang = ""
	scanSeverities = []string{"bad"}
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("invalid severity accepted")
	}
	scanSeverities = nil
	scanInput = []string{"invalid-input"}
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("invalid input accepted")
	}
	scanInput = nil
	scanPolicies = []string{filepath.Join(dir, "missing.rego")}
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("missing policy accepted")
	}
	scanPolicies = []string{policyFile}
	emptyDir := filepath.Join(dir, "empty")
	if err := os.Mkdir(emptyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := runScan(nil, []string{emptyDir}); err == nil {
		t.Fatal("empty input directory accepted")
	}
	if err := runScan(nil, []string{badFile, rosFile}); err != nil {
		t.Fatalf("valid file skipped after invalid file: %v", err)
	}
	invalidPolicy := filepath.Join(dir, "invalid.rego")
	if err := os.WriteFile(invalidPolicy, []byte("invalid rego"), 0644); err != nil {
		t.Fatal(err)
	}
	scanPolicies = []string{invalidPolicy}
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("invalid policy accepted")
	}
	scanPolicies, scanFormat, scanOutput = []string{policyFile}, "html", filepath.Join(dir, "missing", "report.html")
	if err := runScan(nil, []string{rosFile}); err == nil {
		t.Fatal("unwritable report path accepted")
	}
}

func TestParsePolicySpecPaths(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	nested := filepath.Join(dir, "policies", "nested")
	for _, path := range []string{empty, nested} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	rego := filepath.Join(nested, "rule.rego")
	other := filepath.Join(dir, "other.txt")
	for _, path := range []string{rego, other} {
		if err := os.WriteFile(path, []byte("package example"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		path, kind string
		bad        bool
	}{
		{filepath.Join(dir, "missing"), "", true}, {empty, "", true}, {other, "", true},
		{rego, "file", false}, {filepath.Dir(nested), "dir", false},
	} {
		spec, err := parsePolicySpec(tc.path)
		if tc.bad {
			if err == nil {
				t.Errorf("expected error for %q", tc.path)
			}
			continue
		}
		if err != nil || spec.Type != tc.kind || spec.Value != tc.path {
			t.Errorf("%q: %+v %v", tc.path, spec, err)
		}
	}
}

func TestBuildScanOptionsUsesPolicyFilesWhenContentIsNotEmbedded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	rule := &models.Rule{ID: "rule:aliyun:local-file", Severity: "high", IaCTypes: []string{"ros"}, FilePath: filepath.Join(home, "local.rego")}
	pack := &models.Pack{ID: "pack:aliyun:local-pack", RuleIDs: []string{rule.ID}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule}, PackList: []*models.Pack{pack}}
	for _, pattern := range []string{rule.ID, "rule:aliyun:local-*", pack.ID, "pack:aliyun:local-*"} {
		t.Run(pattern, func(t *testing.T) {
			spec, err := parsePolicySpec(pattern)
			if err != nil {
				t.Fatal(err)
			}
			opts, _, err := buildEvalOptions([]*PolicySpec{spec}, i18n.Msg(), map[string]bool{"high": true})
			if err != nil || len(opts.PolicyPaths) != 1 || opts.PolicyPaths[0] != rule.FilePath {
				t.Fatalf("opts=%+v err=%v", opts, err)
			}
			if _, _, err := buildEvalOptions([]*PolicySpec{spec}, i18n.Msg(), map[string]bool{"low": true}); err == nil {
				t.Fatal("severity with no matching rules accepted")
			}
		})
	}
	opts, _, err := buildEvalOptions(nil, i18n.Msg(), nil)
	if err != nil || len(opts.PolicyPaths) != 1 || opts.PolicyPaths[0] != rule.FilePath {
		t.Fatalf("fallback opts=%+v err=%v", opts, err)
	}
}

func TestScanCommandAppliesWaiverToRealViolation(t *testing.T) {
	oldPolicies, oldFormat, oldInput, oldMode, oldWaivers := scanPolicies, scanFormat, scanInput, scanMode, scanWaivers
	oldSeverities, oldLang, oldNoWaivers, oldShow, oldFail, oldStdout := scanSeverities, globalLang, scanNoWaivers, scanShowWaived, scanFailOnExpired, os.Stdout
	t.Cleanup(func() {
		scanPolicies, scanFormat, scanInput, scanMode, scanWaivers = oldPolicies, oldFormat, oldInput, oldMode, oldWaivers
		scanSeverities, globalLang, scanNoWaivers, scanShowWaived, scanFailOnExpired, os.Stdout = oldSeverities, oldLang, oldNoWaivers, oldShow, oldFail, oldStdout
	})
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	rego := `package infraguard.rules.test.sample
import rego.v1
deny contains result if {
 input.Resources.Thing.Properties.Public == true
 result := {"id":"sample", "resource_id":"Thing", "violation_path":["Properties","Public"], "meta":{"severity":"high", "reason":"public access"}}
}`
	policyFile := filepath.Join(dir, "rule.rego")
	if err := os.WriteFile(policyFile, []byte(rego), 0600); err != nil {
		t.Fatal(err)
	}
	templateFile := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(templateFile, []byte("ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n    Properties:\n      Public: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waiverFile := filepath.Join(dir, "waivers.yaml")
	if err := waiver.Save(waiverFile, []waiver.Waiver{{Rule: "sample", Resource: "Thing", Reason: "approved", Expires: "2099-01-01"}}); err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(filepath.Join(dir, "output.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	os.Stdout = output
	scanPolicies, scanFormat, scanInput, scanMode, scanWaivers = []string{policyFile}, "json", nil, "static", waiverFile
	scanSeverities, globalLang, scanNoWaivers, scanShowWaived, scanFailOnExpired = nil, "", false, true, true
	if err := runScan(nil, []string{templateFile}); err != nil {
		t.Fatal(err)
	}
	os.Stdout = oldStdout
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	var report models.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("JSON %q: %v", data, err)
	}
	if report.Summary.TotalViolations != 0 || report.Summary.WaivedCount != 1 || len(report.Results) != 1 || len(report.Results[0].Violations) != 1 || report.Results[0].Violations[0].Waiver == nil || report.Results[0].Violations[0].Waiver.Reason != "approved" {
		t.Fatalf("report=%+v", report)
	}
}

func TestScanFilteringAndMalformedResourceMetadata(t *testing.T) {
	if specs, err := parsePolicySpecs(nil); err != nil || specs != nil {
		t.Fatalf("empty specs: %v %v", specs, err)
	}
	if filter, err := parseScanSeverityFilter([]string{" , "}); err != nil || filter != nil {
		t.Fatalf("empty severity: %v %v", filter, err)
	}
	if ruleMatchesScanSeverity(nil, map[string]bool{"high": true}) {
		t.Fatal("nil rule matched severity")
	}
	if got := extractShortRuleID("rule:invalid"); got != "rule:invalid" {
		t.Fatalf("short rule ID: %q", got)
	}
	if toInt(int64(9)) != 9 || toInt("bad") != 0 {
		t.Fatal("invalid line conversion")
	}
	for _, content := range []string{"- item", "Resources: []", "Parameters: {}"} {
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(content), &root); err != nil {
			t.Fatal(err)
		}
		if got := extractROSResourceLines(&root); len(got) != 0 {
			t.Errorf("unexpected resources for %q: %v", content, got)
		}
	}
	data := map[string]interface{}{"resources": map[string]interface{}{
		"bad-type": "text",
		"type":     map[string]interface{}{"bad-instance": "text", "valid": map[string]interface{}{"__meta__": map[string]interface{}{"filename": "main.tf", "line": int64(3)}}},
	}}
	if got := extractTFResourceLines(data, "/project"); len(got[filepath.Join("/project", "main.tf")]) != 1 {
		t.Fatalf("resource metadata: %+v", got)
	}
}
