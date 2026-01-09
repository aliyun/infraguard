// Package mapper provides source code location mapping.
package mapper

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"gopkg.in/yaml.v3"
)

// MapViolations enriches OPA violations with source file context.
// Uses default English language for reason/recommendation.
func MapViolations(violations []models.OPAViolation, yamlRoot interface{}, filePath string) []models.RichViolation {
	return MapViolationsWithLang(violations, yamlRoot, filePath, "en")
}

// SnippetContextLines defines how many lines to show before/after the violation line.
const SnippetContextLines = 2

// MapViolationsWithLang enriches OPA violations with source file context and i18n support.
func MapViolationsWithLang(violations []models.OPAViolation, yamlRoot interface{}, filePath string, lang string) []models.RichViolation {
	var rich []models.RichViolation

	for _, v := range violations {
		rv := models.RichViolation{
			Severity:          v.Meta.Severity,
			ID:                v.ID,
			ResourceID:        v.ResourceID,
			ViolationPath:     pathToStrings(v.ViolationPath),
			File:              filePath,
			Line:              1, // Default to line 1 if mapping fails
			Snippet:           "",
			SnippetLines:      nil,
			Reason:            i18n.FormatMessage(v.Meta.Reason, lang),
			Recommendation:    i18n.FormatMessage(v.Meta.Recommendation, lang),
			ReasonRaw:         v.Meta.Reason,
			RecommendationRaw: v.Meta.Recommendation,
		}

		// Build full path: Resources -> resource_id -> violation_path
		fullPath := buildFullPath(v.ResourceID, v.ViolationPath)

		// Try to find the node in YAML AST
		if node, ok := yamlRoot.(*yaml.Node); ok && node != nil {
			line, snippet, snippetLines := findNode(node, fullPath, filePath)
			if line > 0 {
				rv.Line = line
				rv.Snippet = snippet
				rv.SnippetLines = snippetLines
			}
		}

		rich = append(rich, rv)
	}

	return rich
}

// buildFullPath constructs the full YAML path from resource ID and violation path.
//   - If resourceID is provided (non-empty), treat it as a resource-level check:
//     E.g., resource_id="MyALB", path=["Properties", "SecurityGroupIds"]
//     -> ["Resources", "MyALB", "Properties", "SecurityGroupIds"]
//   - If resourceID is empty, treat violationPath as a complete path:
//     E.g., resource_id="", path=["Metadata", "ALIYUN::ROS::Interface", "TemplateTags"]
//     -> ["Metadata", "ALIYUN::ROS::Interface", "TemplateTags"]
func buildFullPath(resourceID string, violationPath []interface{}) []interface{} {
	// If resourceID is empty, treat violationPath as a complete path
	if resourceID == "" {
		return violationPath
	}

	// For resource-level checks, add Resources prefix
	fullPath := make([]interface{}, 0, len(violationPath)+2)
	fullPath = append(fullPath, "Resources")
	fullPath = append(fullPath, resourceID)
	fullPath = append(fullPath, violationPath...)
	return fullPath
}

// pathToStrings converts a violation path to string slice.
func pathToStrings(path []interface{}) []string {
	result := make([]string, 0, len(path))
	for _, p := range path {
		result = append(result, fmt.Sprintf("%v", p))
	}
	return result
}

// traverseResult holds the result of traversing to a node.
type traverseResult struct {
	keyNode   *yaml.Node // The key node (for getting key's line number)
	valueNode *yaml.Node // The value node (for further traversal)
}

// findNode traverses the YAML AST to find the node at the given path.
// Returns line number, single-line snippet, and multi-line snippet with context.
// If path cannot be fully traversed, returns the closest parent node.
func findNode(root *yaml.Node, path []interface{}, filePath string) (int, string, []models.SnippetLine) {
	if root == nil || len(path) == 0 {
		return 0, "", nil
	}

	// Start from the document node
	current := root
	if current.Kind == yaml.DocumentNode && len(current.Content) > 0 {
		current = current.Content[0]
	}

	lastValidLine := current.Line

	// Traverse the path
	for _, segment := range path {
		result := traverseNode(current, segment)
		if result == nil || result.valueNode == nil {
			// Path interrupted - use last valid position (fallback to parent key's line)
			break
		}
		current = result.valueNode
		// Use the key's line number (e.g., "Properties:" line), not the value's first child
		if result.keyNode != nil {
			lastValidLine = result.keyNode.Line
		} else {
			lastValidLine = current.Line
		}
	}

	// Get snippet from file
	snippet, snippetLines := getSnippetWithContext(filePath, lastValidLine, SnippetContextLines)

	return lastValidLine, snippet, snippetLines
}

// traverseNode moves to the next node based on the path segment.
// Returns both the key node and value node for proper line number tracking.
func traverseNode(node *yaml.Node, segment interface{}) *traverseResult {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		// Look for key matching segment
		key, ok := segment.(string)
		if !ok {
			key = fmt.Sprintf("%v", segment)
		}

		// Content is [key, value, key, value, ...]
		for i := 0; i < len(node.Content)-1; i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			if keyNode.Value == key {
				return &traverseResult{keyNode: keyNode, valueNode: valueNode}
			}
		}

	case yaml.SequenceNode:
		// Look for index
		var idx int
		switch v := segment.(type) {
		case int:
			idx = v
		case float64:
			idx = int(v)
		default:
			return nil
		}

		if idx >= 0 && idx < len(node.Content) {
			return &traverseResult{keyNode: nil, valueNode: node.Content[idx]}
		}

	case yaml.DocumentNode:
		if len(node.Content) > 0 {
			return traverseNode(node.Content[0], segment)
		}
	}

	return nil
}

// getSnippetWithContext reads lines from a file with context around a target line.
// Returns both the single-line snippet and multi-line snippet with context.
func getSnippetWithContext(filePath string, targetLine int, contextLines int) (string, []models.SnippetLine) {
	if targetLine <= 0 {
		return "", nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", nil
	}
	defer file.Close()

	// Calculate line range
	startLine := targetLine - contextLines
	if startLine < 1 {
		startLine = 1
	}
	endLine := targetLine + contextLines

	var snippetLines []models.SnippetLine
	var singleSnippet string

	scanner := bufio.NewScanner(file)
	currentLine := 0
	for scanner.Scan() {
		currentLine++
		if currentLine >= startLine && currentLine <= endLine {
			content := scanner.Text()
			snippetLines = append(snippetLines, models.SnippetLine{
				LineNum:   currentLine,
				Content:   content,
				Highlight: currentLine == targetLine,
			})
			if currentLine == targetLine {
				singleSnippet = strings.TrimSpace(content)
			}
		}
		if currentLine > endLine {
			break
		}
	}

	return singleSnippet, snippetLines
}
