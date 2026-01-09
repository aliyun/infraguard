// Package models defines core data structures for InfraGuard.
package models

import "strings"

// Severity level constants
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// I18nString represents an internationalized string with language-specific values.
type I18nString map[string]string

// Get returns the string for the given language, falling back to English.
func (i I18nString) Get(lang string) string {
	if val, ok := i[lang]; ok {
		return val
	}
	if val, ok := i["en"]; ok {
		return val
	}
	return ""
}

// Rule represents a compliance rule with its metadata.
type Rule struct {
	ID             string     `json:"id"`             // e.g., "rule:aliyun:ecs-public-ip"
	Name           I18nString `json:"name"`           // Localized name
	Severity       string     `json:"severity"`       // high, medium, low
	Description    I18nString `json:"description"`    // What the rule checks
	Reason         I18nString `json:"reason"`         // Why the violation occurred
	Recommendation I18nString `json:"recommendation"` // How to fix
	ResourceTypes  []string   `json:"resource_types"` // Resource types this rule applies to
	FilePath       string     `json:"file_path"`      // Source .rego file path
	PackageName    string     `json:"package_name"`   // Rego package name
	Content        string     `json:"content"`        // Rego content (for embedded)
}

// Pack represents a compliance pack that groups multiple rules.
type Pack struct {
	ID          string     `json:"id"`           // e.g., "pack:aliyun:multi-zone-best-practice"
	Name        I18nString `json:"name"`         // Localized name
	Description I18nString `json:"description"`  // Pack description
	RuleIDs     []string   `json:"rules"`        // List of rule IDs in this pack
	FilePath    string     `json:"file_path"`    // Source .rego file path
	PackageName string     `json:"package_name"` // Rego package name
	Content     string     `json:"content"`      // Rego content (for embedded)
}

// PolicyIndex holds indexed rules and packs for fast lookup.
type PolicyIndex struct {
	Rules      map[string]*Rule  // Indexed by rule ID
	Packs      map[string]*Pack  // Indexed by pack ID
	RuleList   []*Rule           // Ordered list of all rules
	PackList   []*Pack           // Ordered list of all packs
	LibModules map[string]string // Embedded lib modules
}

// AddRule adds a rule to the index.
func (pi *PolicyIndex) AddRule(rule *Rule) {
	pi.Rules[rule.ID] = rule
	pi.RuleList = append(pi.RuleList, rule)
}

// AddPack adds a pack to the index.
func (pi *PolicyIndex) AddPack(pack *Pack) {
	pi.Packs[pack.ID] = pack
	pi.PackList = append(pi.PackList, pack)
}

// GetRule returns a rule by ID.
func (pi *PolicyIndex) GetRule(id string) *Rule {
	return pi.Rules[id]
}

// GetPack returns a pack by ID.
func (pi *PolicyIndex) GetPack(id string) *Pack {
	return pi.Packs[id]
}

// GetRulesForPack returns all rules for a given pack.
func (pi *PolicyIndex) GetRulesForPack(packID string) []*Rule {
	pack := pi.Packs[packID]
	if pack == nil {
		return nil
	}
	rules := make([]*Rule, 0, len(pack.RuleIDs))
	for _, ruleID := range pack.RuleIDs {
		if rule := pi.Rules[ruleID]; rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules
}

// ViolationMeta contains metadata about a violation.
type ViolationMeta struct {
	Severity       string      `json:"severity"`
	Reason         interface{} `json:"reason"`         // String or map[string]string for i18n
	Recommendation interface{} `json:"recommendation"` // String or map[string]string for i18n
}

// OPAViolation represents a violation returned by OPA evaluation.
type OPAViolation struct {
	ID            string        `json:"id"`
	ResourceID    string        `json:"resource_id"`
	ViolationPath []interface{} `json:"violation_path"` // Path to the violation location
	Meta          ViolationMeta `json:"meta"`
}

// SnippetLine represents a single line of code with its line number.
type SnippetLine struct {
	LineNum   int    `json:"line_num"`
	Content   string `json:"content"`
	Highlight bool   `json:"highlight"` // True if this is the violation line
}

// RichViolation extends OPAViolation with source file context.
type RichViolation struct {
	Severity          string        `json:"severity"`
	ID                string        `json:"id"`
	ResourceID        string        `json:"resource_id"`
	ViolationPath     []string      `json:"violation_path"`
	File              string        `json:"file"`
	Line              int           `json:"line"`
	Snippet           string        `json:"snippet"`       // Single line snippet (for JSON backward compat)
	SnippetLines      []SnippetLine `json:"snippet_lines"` // Multi-line snippet with context
	Reason            string        `json:"reason"`
	Recommendation    string        `json:"recommendation"`
	ReasonRaw         interface{}   `json:"-"` // Original i18n data (string or map)
	RecommendationRaw interface{}   `json:"-"` // Original i18n data (string or map)
}

// SeverityOrder returns the sort order for severity (lower = more severe).
func SeverityOrder(severity string) int {
	switch strings.ToLower(severity) {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default:
		return 3
	}
}

// SeverityLevels returns all supported severity levels in order.
func SeverityLevels() []string {
	return []string{SeverityHigh, SeverityMedium, SeverityLow}
}

// NormalizeSeverity converts severity to lowercase standard format.
func NormalizeSeverity(severity string) string {
	s := strings.ToLower(severity)
	switch s {
	case SeverityHigh, SeverityMedium, SeverityLow:
		return s
	default:
		return SeverityMedium // Default to medium if unknown
	}
}

// ReportSummary contains summary statistics for the report.
type ReportSummary struct {
	TotalViolations     int            `json:"total_violations"`
	SeverityCounts      map[string]int `json:"severity_counts"`
	FilesScanned        int            `json:"files_scanned"`
	FilesWithViolations int            `json:"files_with_violations"`
}

// FileResult holds violations for a specific file.
type FileResult struct {
	File       string          `json:"file"`
	Violations []RichViolation `json:"violations"`
}

// Report represents the full scan report for JSON output.
type Report struct {
	SchemaVersion string        `json:"schema_version"` // Changed to string "2.0"
	Summary       ReportSummary `json:"summary"`
	Results       []FileResult  `json:"results"`
}

// TemplateParams represents resolved parameter values for template evaluation.
type TemplateParams map[string]interface{}
