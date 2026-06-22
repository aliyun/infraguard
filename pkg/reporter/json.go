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
		fileHasReal := false
		for _, v := range fileRes.Violations {
			// Suppressed (active-waived) violations are excluded from totals but
			// remain in Results with their waiver annotation for auditing.
			if v.IsSuppressed(r.failOnExpired) {
				continue
			}
			fileHasReal = true
			totalViolations++
			severityCounts[strings.ToLower(v.Severity)]++
		}
		if fileHasReal {
			filesWithViolations++
		}
	}

	waivedCount, expiredCount := r.waiverCounts(results)

	report := models.Report{
		SchemaVersion: "2.0",
		Summary: models.ReportSummary{
			TotalViolations:     totalViolations,
			SeverityCounts:      severityCounts,
			FilesScanned:        len(results),
			FilesWithViolations: filesWithViolations,
			WaivedCount:         waivedCount,
			ExpiredWaiverCount:  expiredCount,
		},
		Results: results,
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
