package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/mapper"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/providers/ros"
	"github.com/aliyun/infraguard/pkg/providers/terraform"
	"github.com/aliyun/infraguard/pkg/waiver"
	"gopkg.in/yaml.v3"
)

// scanRequest is the body of POST /api/scan.
type scanRequest struct {
	Content   string                 `json:"content"`            // raw template text
	Filename  string                 `json:"filename,omitempty"` // used to infer IaC type
	IaC       string                 `json:"iac,omitempty"`      // "ros" | "terraform" (optional)
	Policies  []string               `json:"policies,omitempty"` // rule/pack IDs; empty = all
	Inputs    map[string]interface{} `json:"inputs,omitempty"`   // parameter values
	Lang      string                 `json:"lang,omitempty"`     // message language
	NoWaivers bool                   `json:"no_waivers,omitempty"`
}

// applyScanWaivers annotates violations with workspace + inline waivers.
func applyScanWaivers(rich []models.RichViolation, display, content string, resLines []waiver.ResourceLine) {
	set := &waiver.Set{}
	if p := waiver.FindFile("."); p != "" {
		if s, err := waiver.Load(p); err == nil {
			set = s
		}
	}
	inlineByFile := map[string]map[string][]waiver.Inline{}
	if ins := waiver.ParseInline(display, content); len(ins) > 0 {
		inlineByFile[display] = waiver.AttributeInline(ins, resLines)
	}
	results := []models.FileResult{{File: display, Violations: rich}}
	set.Annotate(results, inlineByFile, time.Now())
}

// scanResponse is returned by POST /api/scan.
type scanResponse struct {
	IaC        string                 `json:"iac"`
	Summary    models.ReportSummary   `json:"summary"`
	Violations []models.RichViolation `json:"violations"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}
	iac := detectIaC(req.IaC, req.Filename, req.Content)
	lang := req.Lang
	if lang == "" {
		lang = "en"
	}

	loader, err := policy.LoadWithFallback()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policies: "+err.Error())
		return
	}
	opts := resolveEvalOptions(loader, req.Policies, iac)
	if len(opts.Modules) == 0 {
		writeJSON(w, http.StatusOK, scanResponse{IaC: iac, Violations: []models.RichViolation{}, Summary: emptySummary()})
		return
	}

	rich, resLines, err := scanContent(iac, req.Content, req.Inputs, opts, lang)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Replace the temp path with a friendly display name.
	display := req.Filename
	if display == "" {
		if iac == "terraform" {
			display = "main.tf"
		} else {
			display = "template.yaml"
		}
	}
	for i := range rich {
		rich[i].File = display
	}
	if !req.NoWaivers {
		applyScanWaivers(rich, display, req.Content, resLines)
	}

	writeJSON(w, http.StatusOK, scanResponse{IaC: iac, Violations: rich, Summary: summarize(rich)})
}

// scanContent writes the template to a temp location and evaluates it, returning
// the violations and the resource start lines (for inline waiver attribution).
func scanContent(iac, content string, inputs map[string]interface{}, opts *engine.EvalOptions, lang string) ([]models.RichViolation, []waiver.ResourceLine, error) {
	dir, err := os.MkdirTemp("", "infraguard-scan-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	if iac == "terraform" {
		path := filepath.Join(dir, "main.tf")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return nil, nil, err
		}
		data, err := terraform.Load(dir, inputs)
		if err != nil {
			return nil, nil, err
		}
		res, err := engine.EvaluateWithOpts(opts, data)
		if err != nil {
			return nil, nil, err
		}
		return mapper.MapTerraformViolations(res.Violations, data, dir, lang), resourceLinesTF(data), nil
	}

	// ROS (YAML/JSON)
	path := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, nil, err
	}
	yamlRoot, data, err := ros.Load(ros.ModeStatic, path, inputs)
	if err != nil {
		return nil, nil, err
	}
	res, err := engine.EvaluateWithOpts(opts, data)
	if err != nil {
		return nil, nil, err
	}
	return mapper.MapViolationsWithLang(res.Violations, yamlRoot, path, lang), resourceLinesROS(yamlRoot), nil
}

// resourceLinesROS extracts top-level resource start lines from a ROS AST.
func resourceLinesROS(root *yaml.Node) []waiver.ResourceLine {
	var out []waiver.ResourceLine
	if root == nil {
		return out
	}
	doc := root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return out
	}
	var res *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "Resources" {
			res = doc.Content[i+1]
			break
		}
	}
	if res == nil || res.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(res.Content); i += 2 {
		out = append(out, waiver.ResourceLine{ID: res.Content[i].Value, Line: res.Content[i].Line})
	}
	return out
}

// resourceLinesTF extracts resource start lines from Terraform OPA input metadata.
func resourceLinesTF(data map[string]interface{}) []waiver.ResourceLine {
	var out []waiver.ResourceLine
	resources, ok := data["resources"].(map[string]interface{})
	if !ok {
		return out
	}
	for resType, insts := range resources {
		tm, ok := insts.(map[string]interface{})
		if !ok {
			continue
		}
		for name, a := range tm {
			attrs, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			meta, ok := attrs["__meta__"].(map[string]interface{})
			if !ok {
				continue
			}
			line := 0
			switch n := meta["line"].(type) {
			case int:
				line = n
			case int64:
				line = int(n)
			case float64:
				line = int(n)
			}
			if line > 0 {
				out = append(out, waiver.ResourceLine{ID: resType + "." + name, Line: line})
			}
		}
	}
	return out
}

// resolveEvalOptions builds engine options from policy specs filtered to one IaC.
func resolveEvalOptions(loader *policy.Loader, specs []string, iac string) *engine.EvalOptions {
	opts := &engine.EvalOptions{
		Modules:    map[string]string{},
		LibModules: loader.GetLibModules(),
		IDMapping:  map[string]string{},
	}
	for _, r := range loader.GetAllRules() {
		short := shortID(r.ID)
		if short != r.ID {
			opts.IDMapping[short] = r.ID
		}
	}

	add := func(r *models.Rule) {
		if r == nil || !containsString(r.IaCTypes, iac) {
			return
		}
		if impl := r.Implementations[iac]; impl != nil && impl.Content != "" {
			opts.Modules[impl.FilePath] = impl.Content
			opts.RuleIDs = append(opts.RuleIDs, r.ID)
		} else if r.Content != "" {
			opts.Modules[r.FilePath] = r.Content
			opts.RuleIDs = append(opts.RuleIDs, r.ID)
		}
	}

	if len(specs) == 0 {
		for _, r := range loader.GetAllRules() {
			add(r)
		}
		return opts
	}
	for _, spec := range specs {
		if strings.HasPrefix(spec, "pack:") {
			if p := loader.GetPack(spec); p != nil {
				for _, ruleID := range p.RuleIDs {
					add(loader.GetRule(ruleID))
				}
			}
			continue
		}
		add(resolveRule(loader, spec))
	}
	return opts
}

// resolveRule looks up a rule by full or short ID.
func resolveRule(loader *policy.Loader, spec string) *models.Rule {
	if r := loader.GetRule(spec); r != nil {
		return r
	}
	return loader.GetRule("rule:aliyun:" + spec)
}

func detectIaC(explicit, filename, content string) string {
	switch strings.ToLower(explicit) {
	case "ros", "terraform":
		return strings.ToLower(explicit)
	}
	if strings.HasSuffix(strings.ToLower(filename), ".tf") {
		return "terraform"
	}
	// Heuristic: HCL resource blocks vs ROS template markers.
	if strings.Contains(content, "ROSTemplateFormatVersion") || strings.Contains(content, "\nResources:") {
		return "ros"
	}
	if strings.Contains(content, "resource \"") || strings.Contains(content, "resource\t") {
		return "terraform"
	}
	return "ros"
}

func summarize(violations []models.RichViolation) models.ReportSummary {
	counts := map[string]int{models.SeverityHigh: 0, models.SeverityMedium: 0, models.SeverityLow: 0}
	total, waived, expired := 0, 0, 0
	for _, v := range violations {
		if v.Waiver != nil {
			switch v.Waiver.Status {
			case models.WaiverStatusActive:
				waived++
				continue // exclude active waivers from totals
			case models.WaiverStatusExpired:
				expired++
			}
		}
		total++
		counts[strings.ToLower(v.Severity)]++
	}
	filesWith := 0
	if total > 0 {
		filesWith = 1
	}
	return models.ReportSummary{
		TotalViolations:     total,
		SeverityCounts:      counts,
		FilesScanned:        1,
		FilesWithViolations: filesWith,
		WaivedCount:         waived,
		ExpiredWaiverCount:  expired,
	}
}

func emptySummary() models.ReportSummary {
	return models.ReportSummary{
		SeverityCounts: map[string]int{models.SeverityHigh: 0, models.SeverityMedium: 0, models.SeverityLow: 0},
		FilesScanned:   1,
	}
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func shortID(id string) string {
	if !strings.HasPrefix(id, "rule:") && !strings.HasPrefix(id, "pack:") {
		return id
	}
	parts := strings.Split(id, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return id
}
