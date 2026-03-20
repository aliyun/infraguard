package template

import (
	"strings"
)

// ContextType describes the semantic context at a cursor position.
type ContextType int

const (
	ContextUnknown ContextType = iota
	ContextTopLevel
	ContextResourceBlock
	ContextResourceType
	ContextResourceProperties
	ContextPropertyValue
	ContextRefValue
	ContextGetAttResource
	ContextGetAttAttribute
	ContextParameterProperties
	ContextParameterTypeValue
	ContextAssociationPropertyValue
	ContextAssociationPropertyMetadataKey
	ContextAssociationPropertyMetadataParamRef // cursor inside ${...} within a metadata value
	ContextOutputBlock
	ContextLocalsBlock
	ContextLocalsTypeValue
	ContextMappingsBlock
	ContextFindInMapMapName
	ContextFindInMapFirstKey
	ContextFindInMapSecondKey
	ContextConditionsBlock
	ContextConditionValue
	ContextFnIfConditionName
)

// AnalysisContext holds the semantic analysis result at a cursor position.
type AnalysisContext struct {
	Type               ContextType
	ResourceName       string
	ResourceTypeName   string
	PropertyName       string
	PropertyPath       []string // Full path of property names from root Properties to current level
	ExistingKeys       []string
	Prefix             string // Text typed so far at cursor position
	GetAttResourceName string // For ContextGetAttAttribute: the resource logical ID from first param
	ValueStartCol      int    // Column where the value starts (for TextEdit range)
	FindInMapMapName   string // For ContextFindInMapFirstKey/SecondKey: the map name
	FindInMapFirstKey  string // For ContextFindInMapSecondKey: the first-level key
	ParamRefStart      int    // For ContextAssociationPropertyMetadataParamRef: column after "${"
	CurrentParamName   string // The parameter that contains the current AssociationPropertyMetadata
}

// AnalyzePosition determines the semantic context at a given position (0-based line and col).
func AnalyzePosition(content string, line, col int, isYAML bool) *AnalysisContext {
	if isYAML {
		return analyzeYAMLPosition(content, line, col)
	}
	return analyzeJSONPosition(content, line, col)
}

// --- Shared helper functions ---

// CountIndent returns the number of leading whitespace characters in a line.
func CountIndent(line string) int {
	return countIndent(line)
}

// DetectIndentStep detects the indentation step size used in the template
// by looking at the parent line relative to the given line.
func DetectIndentStep(lines []string, lineIdx int) int {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return 2
	}
	indent := countIndent(lines[lineIdx])
	for i := lineIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		lineIndent := countIndent(lines[i])
		if lineIndent < indent {
			step := indent - lineIndent
			if step > 0 {
				return step
			}
			break
		}
	}
	return 2
}

func findValueStartCol(line string) int {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return 0
	}
	pos := idx + 1
	for pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
		pos++
	}
	return pos
}

func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}

func isOutputBlockKey(key string) bool {
	return key == "Value" || key == "Description" || key == "Condition"
}

func isResourceSection(key string) bool {
	sections := []string{"Type", "Properties", "DependsOn", "DeletionPolicy", "Metadata", "Condition", "Count"}
	for _, s := range sections {
		if key == s {
			return true
		}
	}
	return false
}

// HasPropertiesSection checks if the resource block containing the given line
// already has a Properties section at the same indentation level.
func HasPropertiesSection(content string, typeLine int) bool {
	lines := strings.Split(content, "\n")
	if typeLine < 0 || typeLine >= len(lines) {
		return false
	}
	indent := countIndent(lines[typeLine])

	for i := typeLine + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		lineIndent := countIndent(lines[i])
		if lineIndent < indent {
			break
		}
		if lineIndent == indent && hasPropertiesKey(trimmed) {
			return true
		}
	}

	for i := typeLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		lineIndent := countIndent(lines[i])
		if lineIndent < indent {
			break
		}
		if lineIndent == indent && hasPropertiesKey(trimmed) {
			return true
		}
	}

	return false
}

func hasPropertiesKey(trimmed string) bool {
	return strings.HasPrefix(trimmed, "Properties") || strings.HasPrefix(trimmed, `"Properties"`)
}

// --- Shared condition function definitions ---

// conditionFnDef describes a condition-related intrinsic function whose arguments
// reference condition names.
type conditionFnDef struct {
	longForm  string // e.g. "Fn::If"
	shortForm string // e.g. "!If"
	allArgs   bool   // true = all args are condition names (Fn::And, Fn::Or); false = only first arg (Fn::If, Fn::Not)
}

var conditionFns = []conditionFnDef{
	{"Fn::If", "!If", false},
	{"Fn::And", "!And", true},
	{"Fn::Or", "!Or", true},
	{"Fn::Not", "!Not", true},
}
