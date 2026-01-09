package reporter

import (
	"encoding/json"
	"strings"

	"github.com/aliyun/infraguard/pkg/models"
)

// renderJSON outputs violations as JSON.
func (r *Reporter) renderJSON(results []models.FileResult) error {
	// Calculate summary stats
	totalViolations := 0
	filesWithViolations := 0
	severityCounts := map[string]int{
		models.SeverityHigh:   0,
		models.SeverityMedium: 0,
		models.SeverityLow:    0,
	}

	for _, fileRes := range results {
		if len(fileRes.Violations) > 0 {
			filesWithViolations++
			totalViolations += len(fileRes.Violations)
			for _, v := range fileRes.Violations {
				severityCounts[strings.ToLower(v.Severity)]++
			}
		}
	}

	report := models.Report{
		SchemaVersion: "2.0",
		Summary: models.ReportSummary{
			TotalViolations:     totalViolations,
			SeverityCounts:      severityCounts,
			FilesScanned:        len(results),
			FilesWithViolations: filesWithViolations,
		},
		Results: results,
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
