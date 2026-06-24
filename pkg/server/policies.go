package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
)

// ruleSummary is a lightweight rule entry for the catalog list.
type ruleSummary struct {
	ID            string            `json:"id"`
	Name          models.I18nString `json:"name"`
	Severity      string            `json:"severity"`
	IaCTypes      []string          `json:"iac_types"`
	ResourceTypes []string          `json:"resource_types"`
	Services      []string          `json:"services"`
}

type packSummary struct {
	ID          string            `json:"id"`
	Name        models.I18nString `json:"name"`
	Description models.I18nString `json:"description"`
	RuleCount   int               `json:"rule_count"`
}

func (s *Server) handlePoliciesList(w http.ResponseWriter, r *http.Request) {
	loader, err := policy.LoadWithFallback()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policies: "+err.Error())
		return
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	severity := strings.ToLower(r.URL.Query().Get("severity"))
	iac := strings.ToLower(r.URL.Query().Get("iac"))
	service := strings.ToUpper(r.URL.Query().Get("service"))
	resourceType := r.URL.Query().Get("resource_type")
	kind := r.URL.Query().Get("type") // "rule" | "pack" | ""

	rules := []ruleSummary{}
	if kind != "pack" {
		for _, rule := range loader.GetAllRules() {
			if !ruleMatchesFilters(rule, severity, iac, service, resourceType) {
				continue
			}
			if q != "" && !ruleMatchesQuery(rule, q) {
				continue
			}
			rules = append(rules, ruleSummary{
				ID: rule.ID, Name: rule.Name, Severity: rule.Severity,
				IaCTypes: rule.IaCTypes, ResourceTypes: rule.ResourceTypes, Services: servicesFor(rule.ResourceTypes),
			})
		}
		sort.Slice(rules, func(i, j int) bool {
			si, sj := models.SeverityOrder(rules[i].Severity), models.SeverityOrder(rules[j].Severity)
			if si != sj {
				return si < sj
			}
			return rules[i].ID < rules[j].ID
		})
	}

	packs := []packSummary{}
	if kind != "rule" {
		ruleFiltersActive := severity != "" || iac != "" || service != "" || resourceType != ""
		for _, p := range loader.GetAllPacks() {
			if q != "" && !packMatchesQuery(p, q) {
				continue
			}
			if ruleFiltersActive && !packHasMatchingRule(loader, p, severity, iac, service, resourceType) {
				continue
			}
			packs = append(packs, packSummary{ID: p.ID, Name: p.Name, Description: p.Description, RuleCount: len(p.RuleIDs)})
		}
		sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"rules": rules, "packs": packs})
}

// ruleMatchesFilters reports whether a rule passes the rule-level filters.
func ruleMatchesFilters(rule *models.Rule, severity, iac, service, resourceType string) bool {
	if severity != "" && !strings.EqualFold(rule.Severity, severity) {
		return false
	}
	if iac != "" && !containsString(rule.IaCTypes, iac) {
		return false
	}
	if service != "" && !containsString(servicesFor(rule.ResourceTypes), service) {
		return false
	}
	if resourceType != "" && !containsString(rule.ResourceTypes, resourceType) {
		return false
	}
	return true
}

// packHasMatchingRule reports whether a pack contains a rule passing the filters.
func packHasMatchingRule(loader *policy.Loader, p *models.Pack, severity, iac, service, resourceType string) bool {
	for _, id := range p.RuleIDs {
		if rule := loader.GetRule(id); rule != nil && ruleMatchesFilters(rule, severity, iac, service, resourceType) {
			return true
		}
	}
	return false
}

// policyDetail is returned for a single rule or pack.
type policyDetail struct {
	Kind  string        `json:"kind"`
	Rule  *models.Rule  `json:"rule,omitempty"`
	Pack  *models.Pack  `json:"pack,omitempty"`
	Rules []ruleSummary `json:"rules,omitempty"` // resolved rules for a pack
}

func (s *Server) handlePolicyDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	loader, err := policy.LoadWithFallback()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policies: "+err.Error())
		return
	}

	if strings.HasPrefix(id, "pack:") {
		p := loader.GetPack(id)
		if p == nil {
			writeError(w, http.StatusNotFound, "pack not found: "+id)
			return
		}
		var resolved []ruleSummary
		for _, rule := range loader.GetRulesForPack(p.ID) {
			resolved = append(resolved, ruleSummary{
				ID: rule.ID, Name: rule.Name, Severity: rule.Severity,
				IaCTypes: rule.IaCTypes, ResourceTypes: rule.ResourceTypes, Services: servicesFor(rule.ResourceTypes),
			})
		}
		writeJSON(w, http.StatusOK, policyDetail{Kind: "pack", Pack: p, Rules: resolved})
		return
	}

	rule := resolveRule(loader, id)
	if rule == nil {
		writeError(w, http.StatusNotFound, "rule not found: "+id)
		return
	}
	writeJSON(w, http.StatusOK, policyDetail{Kind: "rule", Rule: rule})
}

// coverage describes rule coverage across dimensions.
type coverage struct {
	TotalRules    int                 `json:"total_rules"`
	TotalPacks    int                 `json:"total_packs"`
	BySeverity    map[string]int      `json:"by_severity"`
	ByIaC         map[string]int      `json:"by_iac"`
	ByService     []countEntry        `json:"by_service"`
	ByFramework   []frameworkCoverage `json:"by_framework"`
	ResourceTypes []string            `json:"resource_types"`
}

type countEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type frameworkCoverage struct {
	ID    string            `json:"id"`
	Name  models.I18nString `json:"name"`
	Rules int               `json:"rules"`
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	loader, err := policy.LoadWithFallback()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policies: "+err.Error())
		return
	}
	cov := coverage{
		BySeverity: map[string]int{models.SeverityHigh: 0, models.SeverityMedium: 0, models.SeverityLow: 0},
		ByIaC:      map[string]int{"ros": 0, "terraform": 0, "both": 0},
	}
	serviceCount := map[string]int{}
	resTypeSet := map[string]bool{}
	rules := loader.GetAllRules()
	cov.TotalRules = len(rules)
	for _, rule := range rules {
		cov.BySeverity[strings.ToLower(rule.Severity)]++
		switch {
		case containsString(rule.IaCTypes, "ros") && containsString(rule.IaCTypes, "terraform"):
			cov.ByIaC["both"]++
		case containsString(rule.IaCTypes, "terraform"):
			cov.ByIaC["terraform"]++
		default:
			cov.ByIaC["ros"]++
		}
		for _, svc := range servicesFor(rule.ResourceTypes) {
			serviceCount[svc]++
		}
		for _, rt := range rule.ResourceTypes {
			resTypeSet[rt] = true
		}
	}
	for rt := range resTypeSet {
		cov.ResourceTypes = append(cov.ResourceTypes, rt)
	}
	sort.Strings(cov.ResourceTypes)
	for k, v := range serviceCount {
		cov.ByService = append(cov.ByService, countEntry{Key: k, Count: v})
	}
	sort.Slice(cov.ByService, func(i, j int) bool {
		if cov.ByService[i].Count != cov.ByService[j].Count {
			return cov.ByService[i].Count > cov.ByService[j].Count
		}
		return cov.ByService[i].Key < cov.ByService[j].Key
	})

	packs := loader.GetAllPacks()
	cov.TotalPacks = len(packs)
	for _, p := range packs {
		cov.ByFramework = append(cov.ByFramework, frameworkCoverage{ID: p.ID, Name: p.Name, Rules: len(p.RuleIDs)})
	}
	sort.Slice(cov.ByFramework, func(i, j int) bool { return cov.ByFramework[i].Rules > cov.ByFramework[j].Rules })

	writeJSON(w, http.StatusOK, cov)
}

// servicesFor derives the set of cloud services from resource types.
func servicesFor(resourceTypes []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, rt := range resourceTypes {
		svc := ""
		switch {
		case strings.HasPrefix(rt, "ALIYUN::"):
			parts := strings.Split(rt, "::")
			if len(parts) >= 2 {
				svc = strings.ToUpper(parts[1])
			}
		case strings.HasPrefix(rt, "alicloud_"):
			rest := strings.TrimPrefix(rt, "alicloud_")
			if i := strings.Index(rest, "_"); i > 0 {
				svc = strings.ToUpper(rest[:i])
			} else {
				svc = strings.ToUpper(rest)
			}
		}
		if svc != "" && !seen[svc] {
			seen[svc] = true
			out = append(out, svc)
		}
	}
	sort.Strings(out)
	return out
}

func ruleMatchesQuery(rule *models.Rule, q string) bool {
	if strings.Contains(strings.ToLower(rule.ID), q) {
		return true
	}
	for _, v := range rule.Name {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	for _, rt := range rule.ResourceTypes {
		if strings.Contains(strings.ToLower(rt), q) {
			return true
		}
	}
	return false
}

func packMatchesQuery(p *models.Pack, q string) bool {
	if strings.Contains(strings.ToLower(p.ID), q) {
		return true
	}
	for _, v := range p.Name {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}
