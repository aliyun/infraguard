package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/spf13/cobra"
)

var (
	newIaC            string
	newSeverity       string
	newResourceTypes  []string
	newTFResourceType []string
	newDir            string
	newNameEN         string
	newNameZH         string
	newDescEN         string
	newDescZH         string
	newNoTest         bool
	newForce          bool
	newPack           string
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

var policyNewCmd = &cobra.Command{
	Use:          "new <rule-id>",
	Short:        "", // Set dynamically
	Long:         "", // Set dynamically
	Args:         cobra.MaximumNArgs(1),
	RunE:         runPolicyNew,
	SilenceUsage: true,
}

func init() {
	policyCmd.AddCommand(policyNewCmd)

	policyNewCmd.Flags().StringVar(&newIaC, "iac", "both", "Target IaC: ros, terraform, or both")
	policyNewCmd.Flags().StringVar(&newSeverity, "severity", "medium", "Severity: high, medium, or low")
	policyNewCmd.Flags().StringArrayVar(&newResourceTypes, "resource-type", nil, "ROS resource type (repeatable)")
	policyNewCmd.Flags().StringArrayVar(&newTFResourceType, "tf-resource-type", nil, "Terraform resource type (repeatable)")
	policyNewCmd.Flags().StringVar(&newDir, "dir", "./policies", "Output root directory")
	policyNewCmd.Flags().StringVar(&newNameEN, "name-en", "", "English rule name")
	policyNewCmd.Flags().StringVar(&newNameZH, "name-zh", "", "Chinese rule name")
	policyNewCmd.Flags().StringVar(&newDescEN, "desc-en", "TODO", "English description")
	policyNewCmd.Flags().StringVar(&newDescZH, "desc-zh", "TODO", "Chinese description")
	policyNewCmd.Flags().BoolVar(&newNoTest, "no-test", false, "Do not generate test fixtures")
	policyNewCmd.Flags().BoolVar(&newForce, "force", false, "Overwrite existing files")
	policyNewCmd.Flags().StringVar(&newPack, "pack", "", "Generate a pack skeleton with the given ID instead of a rule")
}

// scaffoldCtx is the template context for rule generation.
type scaffoldCtx struct {
	ID             string
	Snake          string
	Severity       string
	NameEN         string
	NameZH         string
	DescEN         string
	DescZH         string
	ROSTypesList   string // quoted, comma-joined ROS types
	ROSFirstType   string
	TFTypesList    string // quoted, comma-joined TF types
	TFFirstTypeRaw string
}

func runPolicyNew(cmd *cobra.Command, args []string) error {
	if newPack != "" {
		return runPackNew(args)
	}
	if len(args) != 1 {
		return fmt.Errorf("%s", i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrRuleIDReq }))
	}
	id := args[0]
	if !idPattern.MatchString(id) {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrInvalidID }), id)
	}

	switch newSeverity {
	case "high", "medium", "low":
	default:
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrSeverity }), newSeverity)
	}

	genROS, genTF := false, false
	switch newIaC {
	case "ros":
		genROS = true
	case "terraform":
		genTF = true
	case "both":
		genROS, genTF = true, true
	default:
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrIaC }), newIaC)
	}

	if err := ensureRuleIDAvailable(id); err != nil {
		return err
	}

	rosTypes := newResourceTypes
	if len(rosTypes) == 0 {
		rosTypes = []string{"ALIYUN::ECS::Instance"}
	}
	tfTypes := newTFResourceType
	if len(tfTypes) == 0 {
		tfTypes = []string{"alicloud_instance"}
	}

	nameEN := newNameEN
	if nameEN == "" {
		nameEN = id
	}
	nameZH := newNameZH
	if nameZH == "" {
		nameZH = id
	}

	ctx := scaffoldCtx{
		ID:             id,
		Snake:          strings.ReplaceAll(id, "-", "_"),
		Severity:       newSeverity,
		NameEN:         nameEN,
		NameZH:         nameZH,
		DescEN:         newDescEN,
		DescZH:         newDescZH,
		ROSTypesList:   quoteJoin(rosTypes),
		ROSFirstType:   rosTypes[0],
		TFTypesList:    quoteJoin(tfTypes),
		TFFirstTypeRaw: tfTypes[0],
	}

	var created []string

	if genROS {
		path := filepath.Join(newDir, "rules", "ros", id+".rego")
		if err := writeTemplate(path, rosRuleTmpl, ctx); err != nil {
			return err
		}
		created = append(created, path)
		if !newNoTest {
			files, err := writeFixtures(id, "ros", ctx)
			if err != nil {
				return err
			}
			created = append(created, files...)
		}
	}

	if genTF {
		path := filepath.Join(newDir, "rules", "terraform", id+".rego")
		if err := writeTemplate(path, tfRuleTmpl, ctx); err != nil {
			return err
		}
		created = append(created, path)
		if !newNoTest {
			files, err := writeFixtures(id, "terraform", ctx)
			if err != nil {
				return err
			}
			created = append(created, files...)
		}
	}

	greenColor.Printf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.CreatedRule })+"\n", id)
	for _, f := range created {
		fmt.Printf("  %s\n", f)
	}
	fmt.Println()
	boldColor.Println(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.NextSteps }))
	fmt.Println("  " + i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.Step1 }))
	fmt.Println("  " + i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.Step2 }))
	fmt.Printf("  "+i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.Step3 })+"\n", newDir, id)
	return nil
}

func runPackNew(args []string) error {
	id := newPack
	if !idPattern.MatchString(id) {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrInvalidPackID }), id)
	}
	path := filepath.Join(newDir, "packs", id+".rego")
	ctx := scaffoldCtx{ID: id, Snake: strings.ReplaceAll(id, "-", "_"), NameEN: id, NameZH: id}
	if err := writeTemplate(path, packTmpl, ctx); err != nil {
		return err
	}
	greenColor.Printf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.CreatedPack })+"\n", id, path)
	fmt.Println("\n" + i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.PackHint }))
	return nil
}

// ensureRuleIDAvailable checks the embedded index and the target dir for an existing rule.
func ensureRuleIDAvailable(id string) error {
	if newForce {
		return nil
	}
	if loader, err := policy.LoadWithFallback(); err == nil {
		for _, rule := range loader.GetAllRules() {
			if extractShortRuleID(rule.ID) == id {
				return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrExistsBuiltin }), id)
			}
		}
	}
	rulesDir := filepath.Join(newDir, "rules")
	if _, err := os.Stat(rulesDir); err == nil {
		if rules, err := policy.DiscoverRules(rulesDir); err == nil {
			for _, rule := range rules {
				if extractShortRuleID(rule.ID) == id {
					return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrExistsLocal }), id, rulesDir)
				}
			}
		}
	}
	return nil
}

func quoteJoin(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = fmt.Sprintf("%q", it)
	}
	return strings.Join(quoted, ", ")
}

func writeTemplate(path, tmplText string, ctx scaffoldCtx) error {
	if !newForce {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyNew.ErrFileExists }), path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmpl, err := template.New(filepath.Base(path)).Parse(tmplText)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, ctx)
}

func writeFixtures(id, iac string, ctx scaffoldCtx) ([]string, error) {
	base := filepath.Join(newDir, "testdata", "aliyun", "rules", id)
	var created []string
	if iac == "ros" {
		files := map[string]string{
			filepath.Join(base, "ros", "compliant.yaml"): rosCompliantTmpl,
			filepath.Join(base, "ros", "violation.yaml"): rosViolationTmpl,
		}
		for path, tmpl := range files {
			if err := writeTemplate(path, tmpl, ctx); err != nil {
				return nil, err
			}
			created = append(created, path)
		}
	} else {
		files := map[string]string{
			filepath.Join(base, "terraform", "compliant", "main.tf"): tfCompliantTmpl,
			filepath.Join(base, "terraform", "violation", "main.tf"): tfViolationTmpl,
		}
		for path, tmpl := range files {
			if err := writeTemplate(path, tmpl, ctx); err != nil {
				return nil, err
			}
			created = append(created, path)
		}
	}
	return created, nil
}

const rosRuleTmpl = `package infraguard.rules.aliyun.{{.Snake}}

import rego.v1
import data.infraguard.helpers

rule_meta := {
	"id": "{{.ID}}",
	"severity": "{{.Severity}}",
	"name": {
		"en": "{{.NameEN}}",
		"zh": "{{.NameZH}}",
		"ja": "",
		"de": "",
		"es": "",
		"fr": "",
		"pt": ""
	},
	"description": {"en": "{{.DescEN}}", "zh": "{{.DescZH}}"},
	"reason": {"en": "TODO: explain why this is a violation", "zh": "TODO: 说明为什么这是违规"},
	"recommendation": {"en": "TODO: explain how to fix it", "zh": "TODO: 说明如何修复"},
	"resource_types": [{{.ROSTypesList}}]
}

# TODO: implement the compliance condition for this rule.
is_compliant(resource) if {
	helpers.has_property(resource, "TODO_PropertyName")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TODO_PropertyName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
`

const tfRuleTmpl = `package infraguard.rules.terraform.{{.Snake}}

import rego.v1
import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "{{.ID}}",
	"severity": "{{.Severity}}",
	"name": {
		"en": "{{.NameEN}}",
		"zh": "{{.NameZH}}",
		"ja": "",
		"de": "",
		"es": "",
		"fr": "",
		"pt": ""
	},
	"description": {"en": "{{.DescEN}}", "zh": "{{.DescZH}}"},
	"reason": {"en": "TODO: explain why this is a violation", "zh": "TODO: 说明为什么这是违规"},
	"recommendation": {"en": "TODO: explain how to fix it", "zh": "TODO: 说明如何修复"},
	"resource_types": [{{.TFTypesList}}],
	"iac_type": "terraform"
}

# TODO: implement the compliance condition for this rule.
is_compliant(resource) if {
	tf.get_attribute(resource, "TODO_attribute", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("{{.TFFirstTypeRaw}}")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("{{.TFFirstTypeRaw}}.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
`

const rosCompliantTmpl = `ROSTemplateFormatVersion: '2015-09-01'
Description: Compliant fixture for {{.ID}}
Resources:
  CompliantResource:
    Type: {{.ROSFirstType}}
    Properties:
      # TODO: make this resource satisfy the rule
      TODO_PropertyName: example
`

const rosViolationTmpl = `ROSTemplateFormatVersion: '2015-09-01'
Description: Violation fixture for {{.ID}}
Resources:
  ViolatingResource:
    Type: {{.ROSFirstType}}
    # TODO: omit the required property so this triggers {{.ID}}
    Properties:
      Placeholder: true
`

const tfCompliantTmpl = `# Compliant fixture for {{.ID}}
resource "{{.TFFirstTypeRaw}}" "compliant" {
  # TODO: make this resource satisfy the rule
  todo_attribute = true
}
`

const tfViolationTmpl = `# Violation fixture for {{.ID}}
resource "{{.TFFirstTypeRaw}}" "violating" {
  # TODO: this resource should trigger {{.ID}}
  todo_attribute = false
}
`

const packTmpl = `package infraguard.packs.aliyun.{{.Snake}}

import rego.v1

pack_meta := {
	"id": "{{.ID}}",
	"name": {"en": "{{.NameEN}}", "zh": "{{.NameZH}}"},
	"description": {"en": "TODO", "zh": "TODO"},
	"rules": [
		# TODO: add rule IDs, e.g. "oss-bucket-public-read-prohibited"
	]
}
`
