// Package policy manages policy library operations including formatting.
package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/open-policy-agent/opa/v1/format"
)

// FormatResult holds the result of formatting a single file.
type FormatResult struct {
	FilePath  string `json:"file_path"`
	Changed   bool   `json:"changed"`
	Original  string `json:"-"`
	Formatted string `json:"-"`
	Error     error  `json:"error,omitempty"`
}

// FormatSummary holds the summary of formatting results.
type FormatSummary struct {
	TotalFiles     int             `json:"total_files"`
	ChangedFiles   int             `json:"changed_files"`
	UnchangedFiles int             `json:"unchanged_files"`
	ErrorFiles     int             `json:"error_files"`
	Results        []*FormatResult `json:"results"`
}

// isChineseChar checks if a rune is a Chinese character (CJK Unified Ideographs).
func isChineseChar(r rune) bool {
	return r >= 0x4e00 && r <= 0x9fff
}

// isEnglishChar checks if a rune is an English letter or digit.
func isEnglishChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// fixChineseEnglishSpacing fixes spacing between Chinese and English characters in zh fields.
// It adds spaces between Chinese characters and English letters/digits.
func fixChineseEnglishSpacing(content []byte) []byte {
	// Save URLs first to restore later
	urlPattern := regexp.MustCompile(`https?://[^\s"]+`)
	urls := urlPattern.FindAll(content, -1)
	urlPlaceholders := make([]string, len(urls))
	for i, url := range urls {
		placeholder := fmt.Sprintf("__URL_PLACEHOLDER_%d__", i)
		urlPlaceholders[i] = placeholder
		content = bytes.ReplaceAll(content, url, []byte(placeholder))
	}

	// Convert to runes for proper Unicode handling
	runes := []rune(string(content))
	if len(runes) == 0 {
		return content
	}

	var result []rune
	for i := 0; i < len(runes); i++ {
		current := runes[i]
		result = append(result, current)

		// Check if we need to add a space before the next character
		if i < len(runes)-1 {
			next := runes[i+1]

			// Pattern 1: Chinese character followed by English letter/digit
			if isChineseChar(current) && isEnglishChar(next) {
				result = append(result, ' ')
			}

			// Pattern 2: English letter/digit followed by Chinese character
			if isEnglishChar(current) && isChineseChar(next) {
				result = append(result, ' ')
			}
		}
	}

	content = []byte(string(result))

	// Remove duplicate spaces that might have been created
	spacePattern := regexp.MustCompile(` +`)
	content = spacePattern.ReplaceAll(content, []byte(" "))

	// Restore URLs
	for i, placeholder := range urlPlaceholders {
		content = bytes.ReplaceAll(content, []byte(placeholder), urls[i])
	}

	return content
}

// fixZhFieldSpacing fixes spacing in zh field values within the content.
func fixZhFieldSpacing(content []byte) []byte {
	// Pattern to match "zh": "..." with any whitespace
	// This matches both single-line and multi-line formats
	zhPattern := regexp.MustCompile(`("zh"\s*:\s*")([^"]*)(")`)

	return zhPattern.ReplaceAllFunc(content, func(match []byte) []byte {
		submatches := zhPattern.FindSubmatch(match)
		if len(submatches) != 4 {
			return match
		}

		prefix := submatches[1]
		zhValue := submatches[2]
		suffix := submatches[3]

		// Check if it contains Chinese characters
		hasChinese := false
		for _, r := range string(zhValue) {
			if isChineseChar(r) {
				hasChinese = true
				break
			}
		}

		// Only fix if it contains Chinese characters
		if hasChinese {
			fixedValue := fixChineseEnglishSpacing(zhValue)
			return append(append(prefix, fixedValue...), suffix...)
		}

		return match
	})
}

// formatInlineI18nDict formats inline i18n dictionaries (with "en" and "zh" keys) to multiline format.
// Example: {"en": "text", "zh": "文本"} -> {\n\t\t"en": "text",\n\t\t"zh": "文本"\n\t}
func formatInlineI18nDict(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	var result []string

	for _, line := range lines {
		// Pattern to match inline dictionaries with "en" and "zh" keys
		// Matches: {"en": "...", "zh": "..."} or {"zh": "...", "en": "..."}
		inlinePattern := regexp.MustCompile(`(\s*)([^:]*):\s*\{\s*"en"\s*:\s*"([^"]*)"\s*,\s*"zh"\s*:\s*"([^"]*)"\s*\}(,?)`)
		inlinePattern2 := regexp.MustCompile(`(\s*)([^:]*):\s*\{\s*"zh"\s*:\s*"([^"]*)"\s*,\s*"en"\s*:\s*"([^"]*)"\s*\}(,?)`)

		// Try first pattern: {"en": "...", "zh": "..."}
		if matches := inlinePattern.FindStringSubmatch(line); len(matches) == 6 {
			indent := matches[1]
			key := matches[2]
			enValue := matches[3]
			zhValue := matches[4]
			trailingComma := matches[5]

			// Format as multiline with proper indentation
			formatted := fmt.Sprintf("%s%s: {\n%s\t\"en\": \"%s\",\n%s\t\"zh\": \"%s\"\n%s}%s",
				indent, key, indent, enValue, indent, zhValue, indent, trailingComma)
			result = append(result, formatted)
			continue
		}

		// Try second pattern: {"zh": "...", "en": "..."}
		if matches := inlinePattern2.FindStringSubmatch(line); len(matches) == 6 {
			indent := matches[1]
			key := matches[2]
			zhValue := matches[3]
			enValue := matches[4]
			trailingComma := matches[5]

			// Format as multiline (always put en first for consistency)
			formatted := fmt.Sprintf("%s%s: {\n%s\t\"en\": \"%s\",\n%s\t\"zh\": \"%s\"\n%s}%s",
				indent, key, indent, enValue, indent, zhValue, indent, trailingComma)
			result = append(result, formatted)
			continue
		}

		// No match, keep original line
		result = append(result, line)
	}

	return []byte(strings.Join(result, "\n"))
}

// FormatFile formats a single Rego file and returns the result.
// If write is true, the formatted content is written back to the file.
func FormatFile(filePath string, write bool) (*FormatResult, error) {
	msg := i18n.Msg()
	content, err := os.ReadFile(filePath)
	if err != nil {
		return &FormatResult{
			FilePath: filePath,
			Error:    fmt.Errorf(msg.Errors.ReadFile, err),
		}, nil
	}

	originalContent := make([]byte, len(content))
	copy(originalContent, content)

	// First, format using OPA formatter
	formatted, err := format.Source(filePath, content)
	if err != nil {
		return &FormatResult{
			FilePath: filePath,
			Error:    fmt.Errorf(msg.Errors.FormatFile, err),
		}, nil
	}

	// Then, format inline i18n dictionaries to multiline format
	formatted = formatInlineI18nDict(formatted)

	// Finally, fix Chinese-English spacing in zh fields
	formatted = fixZhFieldSpacing(formatted)

	changed := !bytes.Equal(originalContent, formatted)

	result := &FormatResult{
		FilePath:  filePath,
		Changed:   changed,
		Original:  string(originalContent),
		Formatted: string(formatted),
	}

	if write && changed {
		if err := os.WriteFile(filePath, formatted, 0644); err != nil {
			result.Error = fmt.Errorf(msg.Errors.WriteFile, err)
		}
	}

	return result, nil
}

// FormatDirectory formats all Rego files in a directory recursively.
func FormatDirectory(dir string, write bool) (*FormatSummary, error) {
	summary := &FormatSummary{
		Results: []*FormatResult{},
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		result, err := FormatFile(path, write)
		if err != nil {
			return err
		}

		summary.Results = append(summary.Results, result)
		summary.TotalFiles++

		if result.Error != nil {
			summary.ErrorFiles++
		} else if result.Changed {
			summary.ChangedFiles++
		} else {
			summary.UnchangedFiles++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summary, nil
}

// FormatPath formats a file or directory.
func FormatPath(path string, write bool) (*FormatSummary, error) {
	msg := i18n.Msg()
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.PathDoesNotExist, path)
	}

	if info.IsDir() {
		return FormatDirectory(path, write)
	}

	// Single file
	if !strings.HasSuffix(path, ".rego") {
		return nil, fmt.Errorf(msg.Errors.FileMustBeRego, path)
	}

	result, err := FormatFile(path, write)
	if err != nil {
		return nil, err
	}

	summary := &FormatSummary{
		TotalFiles: 1,
		Results:    []*FormatResult{result},
	}

	if result.Error != nil {
		summary.ErrorFiles = 1
	} else if result.Changed {
		summary.ChangedFiles = 1
	} else {
		summary.UnchangedFiles = 1
	}

	return summary, nil
}

// GenerateDiff generates a unified diff between original and formatted content.
func GenerateDiff(original, formatted, filePath string) string {
	if original == formatted {
		return ""
	}

	var buf strings.Builder

	origLines := strings.Split(original, "\n")
	fmtLines := strings.Split(formatted, "\n")

	buf.WriteString(fmt.Sprintf("--- %s (original)\n", filePath))
	buf.WriteString(fmt.Sprintf("+++ %s (formatted)\n", filePath))

	// Simple line-by-line diff
	maxLines := len(origLines)
	if len(fmtLines) > maxLines {
		maxLines = len(fmtLines)
	}

	for i := 0; i < maxLines; i++ {
		origLine := ""
		fmtLine := ""

		if i < len(origLines) {
			origLine = origLines[i]
		}
		if i < len(fmtLines) {
			fmtLine = fmtLines[i]
		}

		if origLine != fmtLine {
			if origLine != "" {
				buf.WriteString(fmt.Sprintf("-%s\n", origLine))
			}
			if fmtLine != "" {
				buf.WriteString(fmt.Sprintf("+%s\n", fmtLine))
			}
		}
	}

	return buf.String()
}
