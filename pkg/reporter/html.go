package reporter

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
)

//go:embed templates/*.html
var templatesFS embed.FS

// I18nData holds translations for all supported languages for client-side switching.
// Structure: map[language_code]map[message_key]translated_string
// Example: {"en": {"title": "Compliance Report", "severityHigh": "High"}, "zh": {...}}
type I18nData map[string]map[string]string

// HTMLData holds data for HTML template rendering.
type HTMLData struct {
	Lang                 string
	Title                string
	TotalViolations      string
	Severity             string
	RuleID               string
	Resource             string
	Location             string
	LineLabel            string
	Reason               string
	Recommendation       string
	TotalViolationsLabel string
	NoViolations         string
	TOC                  string
	Results              []HTMLFileResult // Grouped by file, then by rule
	TotalViolationsCount int
	SeverityCounts       map[string]int
	SeverityLabels       map[string]string
	I18nJSON             template.JS // JSON-serialized I18nData for client-side use
}

// HTMLFileResult represents violations grouped by file.
type HTMLFileResult struct {
	FilePath       string
	Rules          []HTMLRuleResult
	ViolationCount int
}

// HTMLRuleResult represents violations grouped by rule within a file.
type HTMLRuleResult struct {
	RuleID            string
	Severity          string
	LocalizedSeverity string
	ViolationCount    int
	Violations        []HTMLViolation
}

// HTMLViolation represents a violation with localized severity and i18n content.
type HTMLViolation struct {
	models.RichViolation
	LocalizedSeverity string
	SeverityClass     string
	ReasonEN          string
	ReasonZH          string
	RecommendationEN  string
	RecommendationZH  string
}

// renderHTML outputs violations as an HTML document.
func (r *Reporter) renderHTML(results []models.FileResult) error {
	msg := i18n.Msg()
	lang := i18n.GetLanguage()

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"add": func(a, b int) int {
			return a + b
		},
		"truncatePath": func(path string, maxLevels int) string {
			parts := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
			if len(parts) <= maxLevels {
				return path
			}
			return "..." + "/" + strings.Join(parts[len(parts)-maxLevels:], "/")
		},
	}

	tmpl, err := template.New("report.html").Funcs(funcMap).ParseFS(templatesFS, "templates/report.html")
	if err != nil {
		return fmt.Errorf(msg.Errors.ParseHTMLTemplate, err)
	}

	// Group violations by file, then by rule
	htmlResults := make([]HTMLFileResult, 0, len(results))
	totalViolations := 0

	for _, fileResult := range results {
		if len(fileResult.Violations) == 0 {
			continue
		}

		// Group violations by rule ID
		ruleMap := make(map[string][]models.RichViolation)
		for _, v := range fileResult.Violations {
			ruleMap[v.ID] = append(ruleMap[v.ID], v)
		}

		// Convert to HTMLRuleResult
		rules := make([]HTMLRuleResult, 0, len(ruleMap))
		for ruleID, violations := range ruleMap {
			htmlViolations := make([]HTMLViolation, len(violations))
			for idx, v := range violations {
				// Get reason and recommendation in both languages
				reasonEN := i18n.FormatMessage(v.ReasonRaw, "en")
				reasonZH := i18n.FormatMessage(v.ReasonRaw, "zh")
				recommendationEN := i18n.FormatMessage(v.RecommendationRaw, "en")
				recommendationZH := i18n.FormatMessage(v.RecommendationRaw, "zh")

				// If raw data is nil or empty, fall back to the already formatted string
				if reasonEN == "" {
					reasonEN = v.Reason
				}
				if reasonZH == "" {
					reasonZH = v.Reason
				}
				if recommendationEN == "" {
					recommendationEN = v.Recommendation
				}
				if recommendationZH == "" {
					recommendationZH = v.Recommendation
				}

				htmlViolations[idx] = HTMLViolation{
					RichViolation:     v,
					LocalizedSeverity: localizeSeverity(v.Severity, msg),
					SeverityClass:     strings.ToLower(v.Severity),
					ReasonEN:          reasonEN,
					ReasonZH:          reasonZH,
					RecommendationEN:  recommendationEN,
					RecommendationZH:  recommendationZH,
				}
			}

			// Determine severity for the rule (use the first violation's severity)
			severity := strings.ToLower(violations[0].Severity)

			rules = append(rules, HTMLRuleResult{
				RuleID:            ruleID,
				Severity:          severity,
				LocalizedSeverity: localizeSeverity(violations[0].Severity, msg),
				ViolationCount:    len(violations),
				Violations:        htmlViolations,
			})
		}

		// Sort rules by severity: High -> Medium -> Low
		severityOrder := map[string]int{
			models.SeverityHigh:   0,
			models.SeverityMedium: 1,
			models.SeverityLow:    2,
		}
		sort.Slice(rules, func(i, j int) bool {
			return severityOrder[rules[i].Severity] < severityOrder[rules[j].Severity]
		})

		// Count violations for this file
		fileViolationCount := len(fileResult.Violations)
		totalViolations += fileViolationCount

		htmlResults = append(htmlResults, HTMLFileResult{
			FilePath:       fileResult.File,
			Rules:          rules,
			ViolationCount: fileViolationCount,
		})
	}

	// Count violations by severity (normalize to lowercase)
	severityCounts := map[string]int{
		models.SeverityHigh:   0,
		models.SeverityMedium: 0,
		models.SeverityLow:    0,
	}
	for _, fileResult := range htmlResults {
		for _, rule := range fileResult.Rules {
			severityCounts[rule.Severity] += rule.ViolationCount
		}
	}

	// Localized severity labels
	severityLabels := map[string]string{
		models.SeverityHigh:   msg.Severity.High,
		models.SeverityMedium: msg.Severity.Medium,
		models.SeverityLow:    msg.Severity.Low,
	}

	// Generate i18n data dynamically for all supported languages
	i18nData := generateI18nData(totalViolations)

	// Serialize i18n data to JSON for client-side use
	i18nJSON, err := json.Marshal(i18nData)
	if err != nil {
		return fmt.Errorf(msg.Errors.MarshalI18nData, err)
	}

	data := HTMLData{
		Lang:                 lang,
		Title:                msg.Report.Title,
		TotalViolations:      fmt.Sprintf(msg.Report.TotalViolations, totalViolations),
		Severity:             msg.Report.Severity,
		RuleID:               msg.Report.RuleID,
		Resource:             msg.Report.Resource,
		Location:             msg.Report.Location,
		LineLabel:            msg.Report.Line,
		Reason:               msg.Report.Reason,
		Recommendation:       msg.Report.Recommendation,
		TotalViolationsLabel: msg.Report.Total,
		NoViolations:         msg.Scan.NoViolations,
		TOC:                  getTOCLabel(lang),
		Results:              htmlResults,
		TotalViolationsCount: totalViolations,
		SeverityCounts:       severityCounts,
		SeverityLabels:       severityLabels,
		I18nJSON:             template.JS(i18nJSON),
	}

	return tmpl.Execute(r.writer, data)
}

// generateI18nData creates i18n translations for all supported languages.
// This function dynamically generates the i18n data structure for client-side language switching.
func generateI18nData(violationCount int) I18nData {
	data := make(I18nData)
	supportedLangs := i18n.GetSupportedLanguages()

	for _, lang := range supportedLangs {
		msg := i18n.GetMessages(lang)
		data[lang] = map[string]string{
			"title":           msg.Report.Title,
			"totalViolations": fmt.Sprintf(msg.Report.TotalViolations, violationCount),
			"severityHigh":    msg.Severity.High,
			"severityMedium":  msg.Severity.Medium,
			"severityLow":     msg.Severity.Low,
			"ruleId":          msg.Report.RuleID,
			"resource":        msg.Report.Resource,
			"location":        msg.Report.Location,
			"line":            msg.Report.Line,
			"recommendation":  msg.Report.Recommendation,
			"noViolations":    msg.Scan.NoViolations,
			"toc":             getTOCLabel(lang),
			"total":           msg.Report.Total,
		}
	}

	return data
}

// getTOCLabel returns the localized "Table of Contents" label for a given language.
func getTOCLabel(lang string) string {
	// These are hardcoded as they're not in the locale files
	tocLabels := map[string]string{
		"en": "Table of Contents",
		"zh": "目录",
	}
	if label, ok := tocLabels[lang]; ok {
		return label
	}
	return tocLabels["en"] // Fallback to English
}

// localizeSeverity returns the localized severity string.
func localizeSeverity(severity string, msg *i18n.Messages) string {
	switch strings.ToLower(severity) {
	case models.SeverityHigh:
		return msg.Severity.High
	case models.SeverityMedium:
		return msg.Severity.Medium
	case models.SeverityLow:
		return msg.Severity.Low
	default:
		return severity
	}
}
