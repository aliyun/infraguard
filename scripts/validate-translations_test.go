//go:build ignore

package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/config"
)

func TestTranslationCommandFailureExits(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		files      map[string]string
	}{
		{"missing directory", "Error loading translation files", nil},
		{"no files", "No translation files found", map[string]string{}},
		{"invalid yaml", "failed to parse", map[string]string{"en.yaml": "[broken"}},
		{"missing English", "English reference file not found", map[string]string{"zh.yaml": "greeting: hello\n"}},
		{"missing translation", "Validation failed", map[string]string{"en.yaml": "greeting: hello\n", "zh.yaml": "other: hi\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.files != nil {
				dir := filepath.Join(root, "pkg", "i18n", "locales")
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				for name, content := range tc.files {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestTranslationFailureHelper$")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "INFRAGUARD_TRANSLATION_FAILURE_TEST=1")
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), tc.want) {
				t.Fatalf("failure: output=%q error=%v", output, err)
			}
		})
	}
}

func TestTranslationFailureHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_TRANSLATION_FAILURE_TEST") != "1" || flag.Lookup("test.run").Value.String() != "^TestTranslationFailureHelper$" {
		return
	}
	main()
	t.Fatal("translation validation unexpectedly succeeded")
}

func TestTranslationFilesAndKeys(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadTranslationFiles(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing directory error")
	}
	if err := os.WriteFile(filepath.Join(dir, "en.yaml"), []byte("a:\n  b: hello\n  c: world\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("ignored"), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := loadTranslationFiles(dir)
	if err != nil || len(files) != 1 || files[0].Lang != "en" {
		t.Fatalf("files: %+v %v", files, err)
	}
	missing := findMissingKeys(files[0].Keys, map[string]interface{}{"a": map[string]interface{}{"b": "translated"}}, "")
	sort.Strings(missing)
	if !reflect.DeepEqual(missing, []string{"a.c"}) {
		t.Fatalf("missing keys: %v", missing)
	}
	if got := findMissingKeys(files[0].Keys, map[string]interface{}{"a": "wrong type"}, ""); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("type mismatch: %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("[broken"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTranslationFiles(dir); err == nil {
		t.Fatal("invalid YAML accepted")
	}
}

func TestValidatePolicyTranslationsForRulesAndPacks(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	for _, dir := range []string{"policies/aliyun/rules", "policies/aliyun/packs"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	var translations []string
	for _, lang := range config.ValidLangValues {
		translations = append(translations, `"`+lang+`": "value"`)
	}
	values := "{" + strings.Join(translations, ", ") + "}"
	fields := `"name": ` + values + `, "description": ` + values
	rule := `rule_meta := {` + fields + `, "reason": ` + values + `, "recommendation": ` + values + `}`
	pack := `pack_meta := {` + fields + `}`
	rulePath, packPath := "policies/aliyun/rules/sample.rego", "policies/aliyun/packs/sample.rego"
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(rulePath, rule)
	write(packPath, pack)
	if validatePoliciesTranslations() {
		t.Fatal("complete translations rejected")
	}
	write(rulePath, `rule_meta := {"name": {"en": "only English"}}`)
	if !validatePoliciesTranslations() {
		t.Fatal("incomplete rule translations accepted")
	}
	write(rulePath, rule)
	write(packPath, `pack_meta := {"name": {"en": "only English"}}`)
	if !validatePoliciesTranslations() {
		t.Fatal("incomplete pack translations accepted")
	}
	if err := os.RemoveAll("policies/aliyun/packs"); err != nil {
		t.Fatal(err)
	}
	if !validatePoliciesTranslations() {
		t.Fatal("missing packs directory accepted")
	}
	if err := os.RemoveAll("policies/aliyun/rules"); err != nil {
		t.Fatal(err)
	}
	if !validatePoliciesTranslations() {
		t.Fatal("missing rules directory accepted")
	}
}

func TestValidateTranslationsCommand(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	for _, dir := range []string{"pkg/i18n/locales", "policies/aliyun/rules", "policies/aliyun/packs"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, lang := range config.ValidLangValues {
		if err := os.WriteFile(filepath.Join("pkg/i18n/locales", lang+".yaml"), []byte("greeting: hello\nnested:\n  value: test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateLanguageConsistency(); err != nil {
		t.Fatal(err)
	}
	main()
	old := config.ValidLangValues
	t.Cleanup(func() { config.ValidLangValues = old })
	config.ValidLangValues = append(append([]string(nil), old...), "unsupported")
	if err := validateLanguageConsistency(); err == nil {
		t.Fatal("extra configured language accepted")
	}
	config.ValidLangValues = []string{"en"}
	if err := validateLanguageConsistency(); err == nil {
		t.Fatal("missing configured languages accepted")
	}
}

func TestPolicyTranslationMetadata(t *testing.T) {
	rule, err := os.ReadFile("../pkg/policy/testdata/validate/valid/valid-rule.rego")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := extractPolicyMeta(string(rule), "rule.rego", "rule")
	if err != nil || meta == nil || meta.ID != "valid-test-rule" || meta.Name["en"] != "Valid Test Rule" {
		t.Fatalf("metadata: %+v %v", meta, err)
	}
	langs := map[string]bool{"en": true, "zh": true}
	if validatePolicyMeta(*meta, langs, []string{"name", "description", "reason", "recommendation"}) {
		t.Fatal("complete metadata reported incomplete")
	}
	if !validatePolicyMeta(*meta, map[string]bool{"fr": true}, []string{"name"}) {
		t.Fatal("missing and invalid languages not detected")
	}
	if !validatePolicyMeta(PolicyMeta{File: "bad"}, langs, []string{"name"}) {
		t.Fatal("missing name not detected")
	}
	if got, err := extractPolicyMeta("package x", "x.rego", "rule"); got != nil || err != nil {
		t.Fatal("unexpected metadata")
	}
	if got, err := extractPolicyMeta("rule_meta := {", "x.rego", "rule"); got != nil || err != nil {
		t.Fatal("unfinished metadata accepted")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.rego"), rule, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skip.rego"), []byte("package skip"), 0644); err != nil {
		t.Fatal(err)
	}
	metas, err := scanPolicyFiles(dir, "rule")
	if err != nil || len(metas) != 1 || metas[0].ID != meta.ID {
		t.Fatalf("scan: %+v %v", metas, err)
	}
	if _, err := scanPolicyFiles(filepath.Join(dir, "missing"), "rule"); err == nil {
		t.Fatal("expected missing directory error")
	}
}
