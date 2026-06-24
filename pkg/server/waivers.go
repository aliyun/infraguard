package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/waiver"
)

// waiversResponse describes the workspace waiver file and its lint findings.
type waiversResponse struct {
	Path    string          `json:"path"`
	Waivers []waiver.Waiver `json:"waivers"`
	Issues  []waiver.Issue  `json:"issues"`
}

func (s *Server) handleWaiversGet(w http.ResponseWriter, r *http.Request) {
	path := waiver.FindFile(".")
	if path == "" {
		path = waiver.WorkspacePath(".")
		writeJSON(w, http.StatusOK, waiversResponse{Path: path, Waivers: []waiver.Waiver{}, Issues: []waiver.Issue{}})
		return
	}
	set, err := waiver.Load(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read waiver file: "+err.Error())
		return
	}
	issues := set.Lint(knownRuleSet(), time.Now())
	if issues == nil {
		issues = []waiver.Issue{}
	}
	writeJSON(w, http.StatusOK, waiversResponse{Path: path, Waivers: set.Waivers, Issues: issues})
}

// waiversSaveRequest is the body of POST /api/waivers.
type waiversSaveRequest struct {
	Waivers []waiver.Waiver `json:"waivers"`
}

func (s *Server) handleWaiversSave(w http.ResponseWriter, r *http.Request) {
	var req waiversSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	path := waiver.FindFile(".")
	if path == "" {
		path = waiver.WorkspacePath(".")
	}
	if err := waiver.Save(path, req.Waivers); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save waiver file: "+err.Error())
		return
	}
	set := &waiver.Set{Path: path, Waivers: req.Waivers}
	issues := set.Lint(knownRuleSet(), time.Now())
	if issues == nil {
		issues = []waiver.Issue{}
	}
	writeJSON(w, http.StatusOK, waiversResponse{Path: path, Waivers: req.Waivers, Issues: issues})
}

// knownRuleSet returns the set of known short rule IDs for waiver linting.
func knownRuleSet() map[string]bool {
	known := map[string]bool{}
	if loader, err := policy.LoadWithFallback(); err == nil {
		for _, rule := range loader.GetAllRules() {
			known[shortID(rule.ID)] = true
		}
	}
	if len(known) == 0 {
		return nil
	}
	return known
}
