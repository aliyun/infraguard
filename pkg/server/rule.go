package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
)

// ruleEvalRequest evaluates ad-hoc Rego against a template.
type ruleEvalRequest struct {
	Rego    string                 `json:"rego"`
	Content string                 `json:"content"`
	IaC     string                 `json:"iac,omitempty"`
	Inputs  map[string]interface{} `json:"inputs,omitempty"`
	Lang    string                 `json:"lang,omitempty"`
}

func (s *Server) handleRuleEval(w http.ResponseWriter, r *http.Request) {
	var req ruleEvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Rego) == "" || strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "rego and content are required")
		return
	}
	lib, err := libModules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	iac := detectIaC(req.IaC, "", req.Content)
	opts := &engine.EvalOptions{
		Modules:    map[string]string{"studio.rego": req.Rego},
		LibModules: lib,
	}
	lang := req.Lang
	if lang == "" {
		lang = "en"
	}
	rich, err := scanContent(iac, req.Content, req.Inputs, opts, lang)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rich == nil {
		rich = []models.RichViolation{}
	}
	for i := range rich {
		rich[i].File = "template"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"iac": iac, "violations": rich})
}

// ruleTestRequest runs compliant/violation fixtures against ad-hoc Rego.
type ruleTestRequest struct {
	Rego      string `json:"rego"`
	IaC       string `json:"iac,omitempty"`
	Compliant string `json:"compliant"`
	Violation string `json:"violation"`
	Lang      string `json:"lang,omitempty"`
}

type caseOutcome struct {
	Violations int    `json:"violations"`
	Pass       bool   `json:"pass"`
	Error      string `json:"error,omitempty"`
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	var req ruleTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Rego) == "" {
		writeError(w, http.StatusBadRequest, "rego is required")
		return
	}
	lib, err := libModules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	iac := detectIaC(req.IaC, "", req.Compliant+req.Violation)
	lang := req.Lang
	if lang == "" {
		lang = "en"
	}
	newOpts := func() *engine.EvalOptions {
		return &engine.EvalOptions{Modules: map[string]string{"studio.rego": req.Rego}, LibModules: lib}
	}

	run := func(content string, expectViolation bool) caseOutcome {
		if strings.TrimSpace(content) == "" {
			return caseOutcome{Pass: false, Error: "fixture is empty"}
		}
		rich, err := scanContent(iac, content, nil, newOpts(), lang)
		if err != nil {
			return caseOutcome{Pass: false, Error: err.Error()}
		}
		n := len(rich)
		pass := n == 0
		if expectViolation {
			pass = n >= 1
		}
		return caseOutcome{Violations: n, Pass: pass}
	}

	compliant := run(req.Compliant, false)
	violation := run(req.Violation, true)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"iac":       iac,
		"compliant": compliant,
		"violation": violation,
		"pass":      compliant.Pass && violation.Pass,
	})
}

func libModules() (map[string]string, error) {
	loader, err := policy.LoadWithFallback()
	if err != nil {
		return nil, err
	}
	return loader.GetLibModules(), nil
}
