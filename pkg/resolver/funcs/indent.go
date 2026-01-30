package funcs

import (
	"fmt"
	"strings"
)

// FnIndent adds indentation to each line of a string
// Fn::Indent: [2, "line1\nline2"] => "  line1\n  line2"
func FnIndent(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Indent requires an array of [indentCount, string]")
	}

	// Resolve indent count
	indentResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Indent: error resolving indent count: %w", err)
	}

	// Convert to int
	var indentCount int
	switch v := indentResolved.(type) {
	case int:
		indentCount = v
	case float64:
		indentCount = int(v)
	default:
		return nil, fmt.Errorf("Fn::Indent: indent count must be a number, got %T", v)
	}

	// Resolve string value
	strResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Indent: error resolving string: %w", err)
	}

	// If still a function, can't indent (not an error, just can't resolve statically)
	if isFunction(strResolved) {
		return map[string]interface{}{"Fn::Indent": value}, nil
	}

	str := fmt.Sprintf("%v", strResolved)

	// Add indentation to each line
	indent := strings.Repeat(" ", indentCount)
	lines := strings.Split(str, "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}

	return strings.Join(lines, "\n"), nil
}
