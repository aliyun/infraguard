package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

// Color functions for TTY output
var (
	highColor   = color.New(color.FgRed, color.Bold)
	mediumColor = color.New(color.FgYellow)
	lowColor    = color.New(color.FgCyan)
	dimColor    = color.New(color.Faint)
	boldColor   = color.New(color.Bold)
	greenColor  = color.New(color.FgGreen)
	redColor    = color.New(color.FgRed)
)

// Severity icons
const (
	iconHigh   = "🔴"
	iconMedium = "🟡"
	iconLow    = "🔵"
)

// renderTable outputs violations in a beautiful tfsec-like format using tablewriter.
func (r *Reporter) renderTable(results []models.FileResult) error {
	msg := i18n.Msg()

	// Check if output is a TTY for color support
	isTTY := false
	if f, ok := r.writer.(*os.File); ok {
		stat, _ := f.Stat()
		isTTY = (stat.Mode() & os.ModeCharDevice) != 0
	}

	totalViolations := 0
	var allViolations []models.RichViolation

	for _, fileRes := range results {
		if len(fileRes.Violations) > 0 {
			totalViolations += len(fileRes.Violations)
			allViolations = append(allViolations, fileRes.Violations...)

			// Print file header
			// Calculate relative path for display
			displayPath := fileRes.File
			if wd, err := os.Getwd(); err == nil {
				if rel, err := filepath.Rel(wd, fileRes.File); err == nil {
					displayPath = rel
				}
			}

			prefix := msg.Scan.FilePrefix
			if isTTY {
				fmt.Fprintf(r.writer, "\n%s %s\n", lowColor.Sprint(prefix), boldColor.Sprint(displayPath))
			} else {
				fmt.Fprintf(r.writer, "\n%s%s\n", prefix, displayPath)
			}

			// Render each violation as a styled card
			for idx, v := range fileRes.Violations {
				if idx > 0 {
					// Add separator between violations
					fmt.Fprintln(r.writer)
				}
				r.renderViolationCard(idx+1, v, isTTY, msg)
			}
			fmt.Fprintln(r.writer)
		}
	}

	if totalViolations == 0 {
		if isTTY {
			greenColor.Fprintln(r.writer, msg.Report.NoViolationsPrefix+msg.Scan.NoViolations)
		} else {
			fmt.Fprintln(r.writer, msg.Scan.NoViolations)
		}
		return nil
	}

	fmt.Fprintln(r.writer)

	// Print summary statistics as table
	r.renderSummary(allViolations, isTTY, msg)

	return nil
}

// renderViolationCard renders a single violation with code snippet table.
func (r *Reporter) renderViolationCard(num int, v models.RichViolation, isTTY bool, msg *i18n.Messages) {
	// Header line with number, severity and reason (bold)
	severityLabel := formatSeverity(v.Severity, isTTY)
	header := fmt.Sprintf(msg.Report.ViolationHeaderFormat, num, v.Reason)

	if isTTY {
		fmt.Fprintf(r.writer, "%s %s\n", severityLabel, boldColor.Sprint(header))
	} else {
		fmt.Fprintf(r.writer, "%s %s\n", v.Severity, header)
	}

	fmt.Fprintln(r.writer)

	// Print file location (file:line format for terminal click support)
	location := fmt.Sprintf(msg.Report.LocationFormat, v.File, v.Line)
	if isTTY {
		fmt.Fprintf(r.writer, msg.Report.MetadataPrefix+"%s\n", dimColor.Sprint(location))
	} else {
		fmt.Fprintf(r.writer, msg.Report.MetadataPrefix+"%s\n", location)
	}

	// Create code snippet table
	if len(v.SnippetLines) > 0 || v.Snippet != "" {
		table := tablewriter.NewTable(r.writer,
			tablewriter.WithRendition(tw.Rendition{
				Settings: tw.Settings{
					Separators: tw.Separators{
						BetweenRows: tw.Off,
					},
				},
			}),
		)

		// Build snippet lines
		snippetLines := v.SnippetLines
		if len(snippetLines) == 0 && v.Snippet != "" {
			snippetLines = []models.SnippetLine{{
				LineNum:   v.Line,
				Content:   v.Snippet,
				Highlight: true,
			}}
		}

		for _, line := range snippetLines {
			// Combine marker and line number into one column
			var linePrefix string
			content := line.Content

			if line.Highlight {
				linePrefix = fmt.Sprintf(msg.Report.LineHighlightPrefix, line.LineNum)
				if isTTY {
					// Highlight violation line in red
					linePrefix = redColor.Sprint(linePrefix)
					content = redColor.Sprint(content)
				}
			} else {
				linePrefix = fmt.Sprintf(msg.Report.LineNormalPrefix, line.LineNum)
				if isTTY {
					linePrefix = dimColor.Sprint(linePrefix)
					content = dimColor.Sprint(content)
				}
			}

			table.Append(linePrefix, content)
		}

		table.Render()
	}

	// Print metadata
	fmt.Fprintln(r.writer)
	r.printMetadata(msg.Report.RuleID, v.ID, isTTY)
	r.printMetadata(msg.Report.Resource, v.ResourceID, isTTY)
	if v.Recommendation != "" {
		r.printMetadata(msg.Report.Recommendation, v.Recommendation, isTTY)
	}
}

// printMetadata prints a key-value metadata line.
func (r *Reporter) printMetadata(key, value string, isTTY bool) {
	msg := i18n.Msg()
	if isTTY {
		fmt.Fprintf(r.writer, msg.Report.MetadataPrefix+"%s"+msg.Report.MetadataSeparator+"%s\n", dimColor.Sprint(key), value)
	} else {
		fmt.Fprintf(r.writer, msg.Report.MetadataPrefix+"%s"+msg.Report.MetadataSeparator+"%s\n", key, value)
	}
}

// formatSeverity returns a formatted severity string with color and icon.
func formatSeverity(severity string, isTTY bool) string {
	msg := i18n.Msg()
	severityLower := strings.ToLower(severity)

	if !isTTY {
		return getSeverityIcon(severityLower) + " " + getSeverityLabel(severityLower, msg)
	}

	switch severityLower {
	case models.SeverityHigh:
		return iconHigh + " " + highColor.Sprint(strings.ToUpper(msg.Severity.High))
	case models.SeverityMedium:
		return iconMedium + " " + mediumColor.Sprint(strings.ToUpper(msg.Severity.Medium))
	case models.SeverityLow:
		return iconLow + " " + lowColor.Sprint(strings.ToUpper(msg.Severity.Low))
	default:
		return severity
	}
}

// getSeverityIcon returns the icon for a severity level.
func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case models.SeverityHigh:
		return iconHigh
	case models.SeverityMedium:
		return iconMedium
	case models.SeverityLow:
		return iconLow
	default:
		return ""
	}
}

// getSeverityLabel returns the localized label for a severity level.
func getSeverityLabel(severity string, msg *i18n.Messages) string {
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

// renderSummary prints a one-line summary with decorative borders.
func (r *Reporter) renderSummary(violations []models.RichViolation, isTTY bool, msg *i18n.Messages) {
	// Count by severity (normalize to lowercase)
	counts := map[string]int{
		models.SeverityHigh:   0,
		models.SeverityMedium: 0,
		models.SeverityLow:    0,
	}
	for _, v := range violations {
		counts[strings.ToLower(v.Severity)]++
	}

	highCount := counts[models.SeverityHigh]
	mediumCount := counts[models.SeverityMedium]
	lowCount := counts[models.SeverityLow]

	// Total is the sum of all severity counts
	totalCount := highCount + mediumCount + lowCount

	// Print decorative header with "Summary" centered
	headerText := msg.Report.Results
	lineWidth := 80
	headerLen := len([]rune(headerText))
	leftPad := (lineWidth - headerLen - 2) / 2
	rightPad := lineWidth - headerLen - 2 - leftPad

	headerLine := strings.Repeat("─", leftPad) + " " + headerText + " " + strings.Repeat("─", rightPad)
	if isTTY {
		dimColor.Fprintln(r.writer, headerLine)
	} else {
		fmt.Fprintln(r.writer, headerLine)
	}

	// Build the summary content
	var parts []string

	// Total (sum of high + medium + low)
	totalPart := fmt.Sprintf("%s: %d", msg.Report.Total, totalCount)
	parts = append(parts, totalPart)

	// High severity
	highPart := fmt.Sprintf("%s: %d", strings.ToUpper(msg.Severity.High), highCount)
	if isTTY && highCount > 0 {
		highPart = highColor.Sprintf("%s: %d", strings.ToUpper(msg.Severity.High), highCount)
	}
	parts = append(parts, highPart)

	// Medium severity
	mediumPart := fmt.Sprintf("%s: %d", strings.ToUpper(msg.Severity.Medium), mediumCount)
	if isTTY && mediumCount > 0 {
		mediumPart = mediumColor.Sprintf("%s: %d", strings.ToUpper(msg.Severity.Medium), mediumCount)
	}
	parts = append(parts, mediumPart)

	// Low severity
	lowPart := fmt.Sprintf("%s: %d", strings.ToUpper(msg.Severity.Low), lowCount)
	if isTTY && lowCount > 0 {
		lowPart = lowColor.Sprintf("%s: %d", strings.ToUpper(msg.Severity.Low), lowCount)
	}
	parts = append(parts, lowPart)

	// Print summary line with padding
	summaryLine := msg.Report.SummaryPrefix + strings.Join(parts, msg.Report.SummarySeparator)
	fmt.Fprintln(r.writer, summaryLine)

	fmt.Fprintln(r.writer)
}
