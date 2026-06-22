// Package reporter provides output formatting and rendering.
package reporter

import (
	"io"
	"sort"

	"github.com/aliyun/infraguard/pkg/models"
)

// Reporter handles violation report rendering.
type Reporter struct {
	format        string
	writer        io.Writer
	showWaived    bool // Render violations suppressed by an active waiver
	failOnExpired bool // Treat expired waivers as real violations
}

// Option configures a Reporter.
type Option func(*Reporter)

// WithShowWaived controls whether waived violations are rendered in table/html output.
func WithShowWaived(v bool) Option { return func(r *Reporter) { r.showWaived = v } }

// WithFailOnExpired controls whether expired waivers count as real violations.
func WithFailOnExpired(v bool) Option { return func(r *Reporter) { r.failOnExpired = v } }

// New creates a new Reporter.
func New(format string, writer io.Writer, opts ...Option) *Reporter {
	r := &Reporter{
		format:        format,
		writer:        writer,
		failOnExpired: true,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// waiverCounts returns the number of active-waived and expired-waived violations.
func (r *Reporter) waiverCounts(results []models.FileResult) (waived, expired int) {
	for _, fr := range results {
		for _, v := range fr.Violations {
			if v.Waiver == nil {
				continue
			}
			switch v.Waiver.Status {
			case models.WaiverStatusActive:
				waived++
			case models.WaiverStatusExpired:
				expired++
			}
		}
	}
	return waived, expired
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
