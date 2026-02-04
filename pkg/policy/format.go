// Package policy manages policy library operations including formatting.
package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/v1/format"
	"github.com/pmezard/go-difflib/difflib"
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

// langEntry represents a language entry with its preceding comments.
type langEntry struct {
	comments []string // Comment lines above this entry
	lang     string   // Language code
	value    string   // The translated value
}

// sortI18nLanguages sorts language keys in i18n dictionaries according to standard order.
// Standard order: en, zh, ja, de, es, fr, pt
// Comments above each entry are preserved and move with the entry.
func sortI18nLanguages(content []byte) []byte {
	// Get standard language order from i18n package
	langOrderMap := i18n.GetLanguageOrderMap()

	lines := strings.Split(string(content), "\n")
	var result []string
	i := 0

	for i < len(lines) {
		line := lines[i]

		// Check if this line is the start of a multiline i18n dictionary
		// Pattern: "name": { or "description": { or "reason": { or "recommendation": {
		if matched, _ := regexp.MatchString(`^\s*"(name|description|reason|recommendation)":\s*\{\s*$`, line); matched {
			// Extract indent and field name
			indentPattern := regexp.MustCompile(`^(\s*)"(name|description|reason|recommendation)":\s*\{\s*$`)
			matches := indentPattern.FindStringSubmatch(line)
			if len(matches) < 3 {
				result = append(result, line)
				i++
				continue
			}

			indent := matches[1]
			fieldName := matches[2]

			// Collect all language entries with their comments
			var entries []langEntry
			var currentComments []string
			j := i + 1

			for j < len(lines) {
				langLine := lines[j]

				// Check if this is the end of dictionary
				if matched, _ := regexp.MatchString(`^\s*\}`, langLine); matched {
					break
				}

				// Check if this is a comment line
				if matched, _ := regexp.MatchString(`^\s*#`, langLine); matched {
					currentComments = append(currentComments, langLine)
					j++
					continue
				}

				// Check if this is a language entry: "en": "...",
				langPattern := regexp.MustCompile(`^\s*"([a-z]{2})":\s*"(.*)",?\s*$`)
				langMatches := langPattern.FindStringSubmatch(langLine)
				if len(langMatches) >= 3 {
					entries = append(entries, langEntry{
						comments: currentComments,
						lang:     langMatches[1],
						value:    langMatches[2],
					})
					currentComments = nil
					j++
				} else {
					// Unknown format, keep as-is
					break
				}
			}

			// Sort entries by language order
			if len(entries) > 0 {
				sort.Slice(entries, func(a, b int) bool {
					orderA, okA := langOrderMap[entries[a].lang]
					orderB, okB := langOrderMap[entries[b].lang]
					if okA && okB {
						return orderA < orderB
					}
					if okA {
						return true
					}
					if okB {
						return false
					}
					return entries[a].lang < entries[b].lang
				})

				result = append(result, fmt.Sprintf("%s\"%s\": {", indent, fieldName))

				// Output sorted entries with comments
				for idx, entry := range entries {
					// Add preceding comments
					result = append(result, entry.comments...)

					trailingComma := ","
					if idx == len(entries)-1 {
						trailingComma = "" // Last entry has no comma
					}
					result = append(result, fmt.Sprintf("%s\t\"%s\": \"%s\"%s", indent, entry.lang, entry.value, trailingComma))
				}

				// Add any remaining comments before closing brace
				result = append(result, currentComments...)

				// Add closing brace
				if j < len(lines) {
					result = append(result, lines[j])
				}

				i = j + 1
				continue
			}
		}

		// Not a multiline i18n dict, keep as-is
		result = append(result, line)
		i++
	}

	return []byte(strings.Join(result, "\n"))
}

// metaField represents a field in meta with its preceding comments.
type metaField struct {
	comments []string // Comment lines above this field
	name     string   // Field name
	lines    []string // Field content lines
}

// sortMetaFields sorts fields in pack_meta and rule_meta according to standard order.
// For pack_meta: id, name, description, rules
// For rule_meta: id, severity, name, description, reason, recommendation, resource_types
// Comments above each field are preserved and move with the field.
func sortMetaFields(content []byte) []byte {
	// Define field orders
	packFieldOrder := []string{"id", "name", "description", "rules"}
	ruleFieldOrder := []string{"id", "severity", "name", "description", "reason", "recommendation", "resource_types"}

	packFieldOrderMap := make(map[string]int)
	for i, field := range packFieldOrder {
		packFieldOrderMap[field] = i
	}

	ruleFieldOrderMap := make(map[string]int)
	for i, field := range ruleFieldOrder {
		ruleFieldOrderMap[field] = i
	}

	lines := strings.Split(string(content), "\n")
	var result []string
	i := 0

	for i < len(lines) {
		line := lines[i]

		// Check if this line is pack_meta or rule_meta
		if matched, _ := regexp.MatchString(`^(pack_meta|rule_meta)\s*:=\s*\{\s*$`, line); matched {
			metaPattern := regexp.MustCompile(`^(pack_meta|rule_meta)\s*:=\s*\{\s*$`)
			matches := metaPattern.FindStringSubmatch(line)
			if len(matches) < 2 {
				result = append(result, line)
				i++
				continue
			}

			metaType := matches[1]
			var fieldOrderMap map[string]int
			if metaType == "pack_meta" {
				fieldOrderMap = packFieldOrderMap
			} else {
				fieldOrderMap = ruleFieldOrderMap
			}

			// Collect all fields with their comments
			var fields []metaField
			var currentComments []string
			j := i + 1

			for j < len(lines) {
				// Check if we've reached the end of meta
				if matched, _ := regexp.MatchString(`^\}\s*$`, lines[j]); matched {
					break
				}

				// Check if this is a comment line
				if matched, _ := regexp.MatchString(`^\s*#`, lines[j]); matched {
					currentComments = append(currentComments, lines[j])
					j++
					continue
				}

				// Check if this is a field start
				fieldPattern := regexp.MustCompile(`^\s*"([a-z_]+)":\s*(.*)$`)
				if fieldMatches := fieldPattern.FindStringSubmatch(lines[j]); len(fieldMatches) >= 3 {
					fieldName := fieldMatches[1]
					fieldValue := fieldMatches[2]

					// Determine if this is a single-line or multi-line field
					if strings.HasSuffix(strings.TrimSpace(fieldValue), ",") || strings.HasSuffix(strings.TrimSpace(fieldValue), "\"") {
						// Single-line field
						fields = append(fields, metaField{
							comments: currentComments,
							name:     fieldName,
							lines:    []string{lines[j]},
						})
						currentComments = nil
						j++
					} else if strings.Contains(fieldValue, "{") || strings.Contains(fieldValue, "[") {
						// Multi-line field (dict or array)
						fieldLines := []string{lines[j]}
						j++

						// Collect until matching closing brace/bracket
						braceCount := strings.Count(fieldValue, "{") + strings.Count(fieldValue, "[")
						braceCount -= strings.Count(fieldValue, "}") + strings.Count(fieldValue, "]")

						for j < len(lines) && braceCount > 0 {
							fieldLines = append(fieldLines, lines[j])
							braceCount += strings.Count(lines[j], "{") + strings.Count(lines[j], "[")
							braceCount -= strings.Count(lines[j], "}") + strings.Count(lines[j], "]")
							j++
						}

						fields = append(fields, metaField{
							comments: currentComments,
							name:     fieldName,
							lines:    fieldLines,
						})
						currentComments = nil
					} else {
						// Unknown format
						j++
					}
				} else {
					j++
				}
			}

			// Sort fields
			sort.Slice(fields, func(a, b int) bool {
				orderA, okA := fieldOrderMap[fields[a].name]
				orderB, okB := fieldOrderMap[fields[b].name]
				if okA && okB {
					return orderA < orderB
				}
				if okA {
					return true
				}
				if okB {
					return false
				}
				return fields[a].name < fields[b].name
			})

			// Output sorted fields
			result = append(result, line) // Add meta declaration line
			for idx, field := range fields {
				// Add preceding comments
				result = append(result, field.comments...)

				// Add field content lines
				for lineIdx, fieldLine := range field.lines {
					// Remove trailing comma from last line of last field
					if idx == len(fields)-1 && lineIdx == len(field.lines)-1 {
						fieldLine = strings.TrimSuffix(strings.TrimRight(fieldLine, " \t"), ",")
					}
					// Add trailing comma to last line of non-last field if missing
					if idx < len(fields)-1 && lineIdx == len(field.lines)-1 {
						if !strings.HasSuffix(strings.TrimRight(fieldLine, " \t"), ",") {
							fieldLine = strings.TrimRight(fieldLine, " \t") + ","
						}
					}
					result = append(result, fieldLine)
				}
			}

			// Add any remaining comments before closing brace
			result = append(result, currentComments...)

			// Add closing brace
			if j < len(lines) {
				result = append(result, lines[j])
			}

			i = j + 1
			continue
		}

		// Not a meta declaration, keep as-is
		result = append(result, line)
		i++
	}

	return []byte(strings.Join(result, "\n"))
}

// arrayElement represents an element in an array with its preceding comments.
type arrayElement struct {
	comments []string // Comment lines above this element
	line     string   // The actual element line
	value    string   // The extracted value for sorting
}

// sortArrayElements sorts elements in arrays (like rules and resource_types).
// Comments above each element are preserved and move with the element.
func sortArrayElements(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	var result []string
	i := 0

	for i < len(lines) {
		line := lines[i]

		// Check if this line starts a rules or resource_types array
		if matched, _ := regexp.MatchString(`^\s*"(rules|resource_types)":\s*\[`, line); matched {
			fieldPattern := regexp.MustCompile(`^(\s*)"(rules|resource_types)":\s*\[(.*)$`)
			matches := fieldPattern.FindStringSubmatch(line)
			if len(matches) < 4 {
				result = append(result, line)
				i++
				continue
			}

			indent := matches[1]
			fieldName := matches[2]
			remainder := matches[3]

			// Check if it's a single-line array
			if strings.Contains(remainder, "]") {
				// Single-line array: ["item1", "item2"] - no comments to handle
				arrayPattern := regexp.MustCompile(`\[([^\]]*)\]`)
				arrayMatches := arrayPattern.FindStringSubmatch(line)
				if len(arrayMatches) >= 2 {
					arrayContent := arrayMatches[1]
					// Parse elements
					elementPattern := regexp.MustCompile(`"([^"]+)"`)
					elementMatches := elementPattern.FindAllStringSubmatch(arrayContent, -1)
					var elements []string
					for _, match := range elementMatches {
						if len(match) >= 2 {
							elements = append(elements, match[1])
						}
					}

					// Sort elements
					sort.Strings(elements)

					// Reconstruct line
					var sortedElements []string
					for _, elem := range elements {
						sortedElements = append(sortedElements, fmt.Sprintf(`"%s"`, elem))
					}
					sortedArray := strings.Join(sortedElements, ", ")

					// Determine trailing comma
					trailingComma := ""
					if strings.HasSuffix(strings.TrimSpace(line), ",") {
						trailingComma = ","
					}

					result = append(result, fmt.Sprintf("%s\"%s\": [%s]%s", indent, fieldName, sortedArray, trailingComma))
					i++
					continue
				}
			}

			// Multi-line array - collect elements with their comments
			var elements []arrayElement
			var currentComments []string
			j := i + 1

			for j < len(lines) {
				// Check for closing bracket
				if matched, _ := regexp.MatchString(`^\s*\]`, lines[j]); matched {
					break
				}

				currentLine := lines[j]

				// Check if this is a comment line (starts with # after whitespace)
				if matched, _ := regexp.MatchString(`^\s*#`, currentLine); matched {
					// Check if it's a commented-out element: # "value",
					commentedElemPattern := regexp.MustCompile(`^\s*#\s*"([^"]+)"[,]?`)
					if elemMatches := commentedElemPattern.FindStringSubmatch(currentLine); len(elemMatches) >= 2 {
						// This is a commented-out element, treat it as an element with empty preceding comments
						elements = append(elements, arrayElement{
							comments: currentComments,
							line:     currentLine,
							value:    elemMatches[1],
						})
						currentComments = nil
					} else {
						// This is a pure comment, add to current comments
						currentComments = append(currentComments, currentLine)
					}
					j++
					continue
				}

				// Extract element value
				elementPattern := regexp.MustCompile(`^\s*"([^"]+)"[,]?\s*$`)
				if elemMatches := elementPattern.FindStringSubmatch(currentLine); len(elemMatches) >= 2 {
					elements = append(elements, arrayElement{
						comments: currentComments,
						line:     currentLine,
						value:    elemMatches[1],
					})
					currentComments = nil
				}
				j++
			}

			// Sort elements by value
			sort.Slice(elements, func(a, b int) bool {
				return elements[a].value < elements[b].value
			})

			// Output sorted array
			result = append(result, fmt.Sprintf("%s\"%s\": [", indent, fieldName))
			for idx, elem := range elements {
				// Add preceding comments
				result = append(result, elem.comments...)

				// Adjust trailing comma
				elemLine := elem.line
				if idx == len(elements)-1 {
					// Remove trailing comma from last element
					elemLine = strings.TrimSuffix(strings.TrimRight(elemLine, " \t"), ",")
				} else {
					// Ensure non-last elements have trailing comma
					trimmed := strings.TrimRight(elemLine, " \t")
					if !strings.HasSuffix(trimmed, ",") {
						elemLine = trimmed + ","
					}
				}
				result = append(result, elemLine)
			}

			// Add any remaining comments before closing bracket
			result = append(result, currentComments...)

			// Add closing bracket
			if j < len(lines) {
				result = append(result, lines[j])
			}

			i = j + 1
			continue
		}

		// Not an array field, keep as-is
		result = append(result, line)
		i++
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

	// Next, sort meta fields (pack_meta and rule_meta)
	formatted = sortMetaFields(formatted)

	// Sort array elements (rules and resource_types)
	formatted = sortArrayElements(formatted)

	// Sort i18n language keys
	formatted = sortI18nLanguages(formatted)

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

// GenerateDiff generates a colored unified diff between original and formatted content.
// Output format matches git diff with hunk headers and colored lines.
func GenerateDiff(original, formatted, filePath string) string {
	if original == formatted {
		return ""
	}

	// Generate unified diff using difflib
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(original),
		B:        difflib.SplitLines(formatted),
		FromFile: filePath + " (original)",
		ToFile:   filePath + " (formatted)",
		Context:  3,
	}

	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return ""
	}

	// Apply colors to diff output
	boldColor := color.New(color.Bold)
	cyanColor := color.New(color.FgCyan)
	redColor := color.New(color.FgRed)
	greenColor := color.New(color.FgGreen)

	var buf strings.Builder
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			buf.WriteString(boldColor.Sprint(line) + "\n")
		} else if strings.HasPrefix(line, "@@") {
			buf.WriteString(cyanColor.Sprint(line) + "\n")
		} else if strings.HasPrefix(line, "-") {
			buf.WriteString(redColor.Sprint(line) + "\n")
		} else if strings.HasPrefix(line, "+") {
			buf.WriteString(greenColor.Sprint(line) + "\n")
		} else if line != "" {
			buf.WriteString(line + "\n")
		}
	}

	return buf.String()
}
