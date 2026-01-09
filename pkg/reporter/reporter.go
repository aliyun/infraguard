// Package reporter provides output formatting and rendering.
package reporter

import (
	"io"
	"sort"

	"github.com/aliyun/infraguard/pkg/models"
)

// Reporter handles violation report rendering.
type Reporter struct {
	format string
	writer io.Writer
}

// New creates a new Reporter.
func New(format string, writer io.Writer) *Reporter {
	return &Reporter{
		format: format,
		writer: writer,
	}
}

// Render outputs the violations in the specified format.
func (r *Reporter) Render(results []models.FileResult) error {
	// Sort results by file path
	sort.Slice(results, func(i, j int) bool {
		return results[i].File < results[j].File
	})

	// Sort violations within each file result by severity (High -> Low)
	for i := range results {
		sort.Slice(results[i].Violations, func(k, l int) bool {
			return models.SeverityOrder(results[i].Violations[k].Severity) < models.SeverityOrder(results[i].Violations[l].Severity)
		})
	}

	switch r.format {
	case "json":
		return r.renderJSON(results)
	case "html":
		return r.renderHTML(results)
	default:
		return r.renderTable(results)
	}
}
