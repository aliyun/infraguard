package reporter

import "strconv"

// FormatPath formats a violation path for display.
func FormatPath(path []string) string {
	result := ""
	for i, p := range path {
		if i > 0 {
			result += "."
		}
		// Check if it's an array index
		if _, err := strconv.Atoi(p); err == nil {
			result += "[" + p + "]"
		} else {
			result += p
		}
	}
	return result
}
