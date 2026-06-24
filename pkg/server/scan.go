package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/mapper"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/providers/ros"
	"github.com/aliyun/infraguard/pkg/providers/terraform"
)

// scanRequest is the body of POST /api/scan.
type scanRequest struct {
	Content  string                 `json:"content"`            // raw template text
	Filename string                 `json:"filename,omitempty"` // used to infer IaC type
	IaC      string                 `json:"iac,omitempty"`      // "ros" | "terraform" (optional)
	Policies []string               `json:"policies,omitempty"` // rule/pack IDs; empty = all
	Inputs   map[string]interface{} `json:"inputs,omitempty"`   // parameter values
	Lang     string                 `json:"lang,omitempty"`     // message language
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

	rich, err := scanContent(iac, req.Content, req.Inputs, opts, lang)
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

	writeJSON(w, http.StatusOK, scanResponse{IaC: iac, Violations: rich, Summary: summarize(rich)})
}

// scanContent writes the template to a temp location and evaluates it.
func scanContent(iac, content string, inputs map[string]interface{}, opts *engine.EvalOptions, lang string) ([]models.RichViolation, error) {
	dir, err := os.MkdirTemp("", "infraguard-scan-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	if iac == "terraform" {
		path := filepath.Join(dir, "main.tf")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return nil, err
		}
		data, err := terraform.Load(dir, inputs)
		if err != nil {
			return nil, err
		}
		res, err := engine.EvaluateWithOpts(opts, data)
		if err != nil {
			return nil, err
		}
		return mapper.MapTerraformViolations(res.Violations, data, dir, lang), nil
	}

	// ROS (YAML/JSON)
	path := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	yamlRoot, data, err := ros.Load(ros.ModeStatic, path, inputs)
	if err != nil {
		return nil, err
	}
	res, err := engine.EvaluateWithOpts(opts, data)
	if err != nil {
		return nil, err
	}
	return mapper.MapViolationsWithLang(res.Violations, yamlRoot, path, lang), nil
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
	for _, v := range violations {
		counts[strings.ToLower(v.Severity)]++
	}
	filesWith := 0
	if len(violations) > 0 {
		filesWith = 1
	}
	return models.ReportSummary{
		TotalViolations:     len(violations),
		SeverityCounts:      counts,
		FilesScanned:        1,
		FilesWithViolations: filesWith,
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
