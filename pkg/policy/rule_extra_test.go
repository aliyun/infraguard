package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseRuleMetadataAndHelperModules(t *testing.T) {
	base := filepath.Join(t.TempDir(), "aliyun", "rules")
	path := filepath.Join(base, "terraform", "sample_rule.rego")
	helper := RegoModule{Path: "helpers.rego", Content: `package helper
name := "From helper"`}
	content := `package infraguard.rules.aliyun.sample
import rego.v1
rule_meta := {"name": data.helper.name, "severity":"HIGH", "reason":{"en":"Reason"}, "resource_types":["alicloud_vpc"]}`
	rule, err := ParseRuleFromContentWithModules(content, path, base, []RegoModule{helper})
	if err != nil || rule == nil || rule.ID != "rule:aliyun:sample-rule" || rule.Name["en"] != "From helper" || rule.Severity != "high" || !reflect.DeepEqual(rule.IaCTypes, []string{"terraform"}) {
		t.Fatalf("rule=%+v err=%v", rule, err)
	}
	for _, tc := range []struct {
		name, content string
		wantErr       bool
	}{
		{"missing package", `rule_meta := {}`, false}, {"invalid rego", "package test\n??", false},
		{"undefined metadata", "package test\nother := true", false}, {"invalid metadata type", "package test\nrule_meta := {\"id\": 123}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRuleFromContentWithModules(tc.content, path, base, nil)
			if got != nil || (err != nil) != tc.wantErr {
				t.Fatalf("rule=%+v err=%v", got, err)
			}
		})
	}
}

func TestParseAndDiscoverPacks(t *testing.T) {
	base := filepath.Join(t.TempDir(), "aliyun", "packs")
	if err := os.MkdirAll(filepath.Join(base, "category"), 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "category", "default_pack.rego")
	content := `package infraguard.packs.aliyun.example
import rego.v1
pack_meta := {"name": "Pack", "description": {"en": "Description"}, "rules": ["short", "rule:other:full"]}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	pack, err := ParsePackFromContentWithPath(content, path, base)
	if err != nil || pack == nil || pack.ID != "pack:aliyun:category:default-pack" || pack.Name["en"] != "Pack" || !reflect.DeepEqual(pack.RuleIDs, []string{"rule:aliyun:short", "rule:other:full"}) {
		t.Fatalf("pack=%+v err=%v", pack, err)
	}
	for _, tc := range []struct {
		name, content string
		wantErr       bool
	}{
		{"no package", `pack_meta := {}`, false}, {"undefined", "package test\nother := true", false},
		{"invalid rego", "package test\n???", false}, {"invalid rules", "package test\npack_meta := {\"rules\": 2}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePackFromContentWithPath(tc.content, path, base)
			if got != nil || (err != nil) != tc.wantErr {
				t.Fatalf("pack=%+v err=%v", got, err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(base, "invalid.rego"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	packs, err := DiscoverPacks(base)
	if err != nil || len(packs) != 1 || packs[0].ID != pack.ID {
		t.Fatalf("discovery=%+v err=%v", packs, err)
	}
	if _, err := DiscoverPacks(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestDiscoverRulesWithLocalHelperAndInvalidFiles(t *testing.T) {
	base := filepath.Join(t.TempDir(), "aliyun", "rules")
	helper := filepath.Join(base, "lib", "helper.rego")
	if err := os.MkdirAll(filepath.Dir(helper), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, []byte("package helper\nname := \"Name\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(base, "example.rego")
	content := `package infraguard.rules.aliyun.example
import rego.v1
rule_meta := {"id":"example", "name":data.helper.name, "reason":"test", "severity":"low"}`
	if err := os.WriteFile(rulePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "bad.rego"), []byte("not rego"), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := DiscoverRules(base)
	if err != nil || len(rules) != 1 || rules[0].ID != "rule:aliyun:example" || rules[0].Name["en"] != "Name" {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	if _, err := DiscoverRules(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
}
