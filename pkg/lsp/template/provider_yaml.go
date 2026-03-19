package template

import (
	"fmt"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
)

type yamlFormatHandler struct{}

func (h *yamlFormatHandler) ParseTemplate(content string) *ParsedTemplate {
	return ParseYAML(content)
}

func (h *yamlFormatHandler) BuildTopLevelSnippet(item *protocol.CompletionItem, blockName string, ctx CompletionContext) {
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	switch blockName {
	case "ROSTemplateFormatVersion":
		item.InsertText = "ROSTemplateFormatVersion: '2015-09-01'"
		item.InsertTextFormat = 0
	case "Description":
		item.InsertText = "Description: $0"
	case "Parameters":
		item.InsertText = "Parameters:\n  ${1:ParameterName}:\n    Type: $0"
	case "Locals":
		item.InsertText = "Locals:\n  ${1:LocalName}:\n    Value: $0"
	case "Resources":
		item.InsertText = "Resources:\n  ${1:LogicalId}:\n    Type: $0"
	case "Outputs":
		item.InsertText = "Outputs:\n  ${1:OutputName}:\n    Value: $0"
	case "Conditions":
		item.InsertText = "Conditions:\n  ${1:ConditionName}:\n    Fn::Equals:\n      - ${2:value1}\n      - ${0:value2}"
	case "Mappings":
		item.InsertText = "Mappings:\n  ${1:MapName}:\n    ${2:FirstKey}:\n      ${3:SecondKey}: ${0:Value}"
	default:
		item.InsertText = blockName + ":\n  $0"
	}
}

func (h *yamlFormatHandler) BuildTypeCompletion(item *protocol.CompletionItem, name string, analysis *AnalysisContext, ctx CompletionContext, lines []string, hasProps bool) {
	newText := name
	if !hasProps {
		required := ctx.Registry.RequiredProperties(name)
		if len(required) > 0 {
			indentStep := DetectIndentStep(lines, ctx.Line)
			propRelativeIndent := strings.Repeat(" ", indentStep)
			newText = name + "\nProperties:"
			for j, prop := range required {
				newText += "\n" + propRelativeIndent + prop + ": ${" + fmt.Sprintf("%d", j+1) + "}"
			}
			item.InsertTextFormat = protocol.InsertTextFormatSnippet
		}
	}

	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: ctx.Col},
		},
		NewText: newText,
	}
}

func (h *yamlFormatHandler) BuildPropertyCompletion(item *protocol.CompletionItem, name string, ctx CompletionContext) {
	item.InsertText = name + ": $0"
}

func (h *yamlFormatHandler) BuildResourceBlockSnippet(item *protocol.CompletionItem, blockName string, analysis *AnalysisContext, ctx CompletionContext) {
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	switch blockName {
	case "Properties":
		item.InsertText = buildYAMLPropertiesSnippet(analysis.ResourceTypeName, ctx.Registry)
	case "Type":
		item.InsertText = "Type: $0"
	case "Metadata":
		item.InsertText = "Metadata:\n  $0"
	default:
		item.InsertText = blockName + ": $0"
	}
}

func (h *yamlFormatHandler) BuildOutputBlockSnippet(item *protocol.CompletionItem, blockName string, ctx CompletionContext) {
	item.InsertTextFormat = protocol.InsertTextFormatSnippet

	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	trimmed := strings.TrimSpace(lineText)

	// If cursor is on the output name line (e.g., "OutputName:|"),
	// prepend newline + relative child indentation.
	// VS Code auto-adds the base indent of the current line to subsequent
	// snippet lines, so we only add the indent step (not the full indent).
	colonIdx := strings.Index(trimmed, ":")
	isOnParentLine := false
	if colonIdx >= 0 {
		key := strings.TrimSpace(trimmed[:colonIdx])
		isOnParentLine = key != "" && !isOutputBlockKey(key)
	}
	if isOnParentLine {
		indentStep := DetectIndentStep(lines, ctx.Line)
		relativeIndent := strings.Repeat(" ", indentStep)
		item.InsertText = "\n" + relativeIndent + blockName + ": $0"
	} else {
		item.InsertText = blockName + ": $0"
	}

	if blockName == "Value" {
		item.Command = &protocol.Command{
			Title:   "Trigger Suggest",
			Command: "editor.action.triggerSuggest",
		}
	}
}

func buildYAMLPropertiesSnippet(resourceType string, registry *schema.Registry) string {
	if resourceType == "" || registry == nil {
		return "Properties:\n  $0"
	}
	required := registry.RequiredProperties(resourceType)
	if len(required) == 0 {
		return "Properties:\n  $0"
	}
	snippet := "Properties:"
	for i, prop := range required {
		snippet += fmt.Sprintf("\n  %s: $%d", prop, i+1)
	}
	return snippet
}

func (h *yamlFormatHandler) BuildParameterPropertySnippet(item *protocol.CompletionItem, prop ROSParameterProperty, ctx CompletionContext) {
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	switch prop.Name {
	case "AllowedValues":
		item.InsertText = "AllowedValues:\n  - $0"
	case "Description":
		item.InsertText = "Description:\n  en: ${1:Description}\n  zh-cn: ${2:描述}"
	case "ConstraintDescription":
		item.InsertText = "ConstraintDescription:\n  en: ${1:ConstraintDescription}\n  zh-cn: ${2:约束描述}"
	case "Label":
		item.InsertText = "Label:\n  en: ${1:Label}\n  zh-cn: ${2:标签}"
	case "Placeholder":
		item.InsertText = "Placeholder:\n  en: ${1:Placeholder}\n  zh-cn: ${2:占位}"
	case "AssociationPropertyMetadata":
		item.InsertText = "AssociationPropertyMetadata:\n  $0"
	default:
		item.InsertText = prop.Name + ": $0"
	}
}

func (h *yamlFormatHandler) BuildLocalsPropertySnippet(item *protocol.CompletionItem, prop ROSLocalsProperty, ctx CompletionContext) {
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	switch prop.Name {
	case "Properties":
		item.InsertText = "Properties:\n  $0"
	case "Type":
		item.InsertText = "Type: $0"
	default:
		item.InsertText = prop.Name + ": $0"
	}
}

func (h *yamlFormatHandler) BuildLocalsTypeValueSnippet(item *protocol.CompletionItem, typeName string, analysis *AnalysisContext, ctx CompletionContext) {
	newText := typeName
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: ctx.Col},
		},
		NewText: newText,
	}
}

func (h *yamlFormatHandler) BuildParameterTypeValueSnippet(item *protocol.CompletionItem, typeName string, analysis *AnalysisContext, ctx CompletionContext) {
	newText := typeName
	if strings.Contains(typeName, "::") {
		newText = "'" + typeName + "'"
	}
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: ctx.Col},
		},
		NewText: newText,
	}
}

func (h *yamlFormatHandler) BuildAssociationPropertyValueSnippet(item *protocol.CompletionItem, name string, analysis *AnalysisContext, ctx CompletionContext) {
	newText := name
	if strings.Contains(name, "::") || strings.Contains(name, "[") {
		newText = "'" + name + "'"
	}
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: ctx.Col},
		},
		NewText: newText,
	}
}

func (h *yamlFormatHandler) BuildAssociationPropertyMetadataKeySnippet(item *protocol.CompletionItem, key string, _ CompletionContext) {
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	item.InsertText = key + ": $0"
}

func (h *yamlFormatHandler) BuildIntrinsicFunctionSnippet(item *protocol.CompletionItem, fn IntrinsicFunction, isShortTag bool, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]

	fnText := fn.Name + ": $0"
	filterText := fn.Name
	if isShortTag {
		fnText = fn.ShortTag + " $0"
		filterText = fn.ShortTag
	}

	col := ctx.Col
	if col > len(lineText) {
		col = len(lineText)
	}
	prefixStart := col
	for prefixStart > 0 {
		ch := lineText[prefixStart-1]
		if ch == ' ' || ch == '\t' {
			break
		}
		prefixStart--
	}

	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	item.FilterText = filterText
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: prefixStart},
			End:   protocol.Position{Line: ctx.Line, Character: col},
		},
		NewText: fnText,
	}
	item.Command = &protocol.Command{
		Title:   "Trigger Suggest",
		Command: "editor.action.triggerSuggest",
	}
}

func (h *yamlFormatHandler) HasShortTags() bool {
	return true
}

func (h *yamlFormatHandler) FindKeyLine(content, key string) int {
	return FindKeyLineInYAML(content, key)
}

func (h *yamlFormatHandler) FindParameterRange(content, paramName string) protocol.Range {
	return findParameterRangeYAML(content, paramName)
}

func (h *yamlFormatHandler) FindParameterAttrValueRange(content, paramName, attrName string) protocol.Range {
	return findParameterAttrValueRangeYAML(content, paramName, attrName)
}

func (h *yamlFormatHandler) FindLocalsRange(content, localName string) protocol.Range {
	return findLocalsRangeYAML(content, localName)
}

func (h *yamlFormatHandler) FindResourceRange(content, resName string) protocol.Range {
	return findResourceRangeYAML(content, resName)
}

func (h *yamlFormatHandler) FindResourceTypeRange(content, resName string) protocol.Range {
	return findResourceTypeRangeYAML(content, resName)
}

func (h *yamlFormatHandler) FindResourcePropertyValueRange(content, resName, propName string) protocol.Range {
	return findResourcePropertyValueRangeYAML(content, resName, propName)
}

func (h *yamlFormatHandler) FindMappingsRange(content, mapName string) protocol.Range {
	return findMappingsRangeYAML(content, mapName)
}

func (h *yamlFormatHandler) FindConditionsRange(content, condName string) protocol.Range {
	return findConditionsRangeYAML(content, condName)
}

func (h *yamlFormatHandler) FindConditionValueRange(content, section, entryName string) protocol.Range {
	return findConditionValueRangeYAML(content, section, entryName)
}

func (h *yamlFormatHandler) ExtractKeyFromLine(line string) string {
	trimmed := strings.TrimSpace(line)
	colonIdx := findYAMLKeySepColon(trimmed)
	if colonIdx <= 0 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:colonIdx])
}

func (h *yamlFormatHandler) ExtractValueFromLine(line string) string {
	trimmed := strings.TrimSpace(line)
	colonIdx := findYAMLKeySepColon(trimmed)
	if colonIdx < 0 || colonIdx >= len(trimmed)-1 {
		return ""
	}
	return strings.TrimSpace(trimmed[colonIdx+1:])
}

func (h *yamlFormatHandler) ValidateFormat(ctx ValidationContext) []protocol.Diagnostic {
	return validateDuplicateKeys(ctx)
}

// --- YAML-specific range finding ---

func findParameterRangeYAML(content, paramName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inParameters := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		ind := countIndent(line)
		if ind == 0 {
			inParameters = strings.HasPrefix(trimmed, "Parameters:") || trimmed == "Parameters"
			continue
		}
		if inParameters && strings.HasPrefix(trimmed, paramName+":") {
			col := strings.Index(line, paramName)
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: col},
				End:   protocol.Position{Line: i, Character: col + len(paramName)},
			}
		}
	}
	return protocol.Range{}
}

func findParameterAttrValueRangeYAML(content, paramName, attrName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inParameters := false
	foundParam := false
	paramIndent := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		ind := countIndent(line)

		if ind == 0 {
			if foundParam {
				break
			}
			inParameters = strings.HasPrefix(trimmed, "Parameters:") || trimmed == "Parameters"
			continue
		}

		if !inParameters {
			continue
		}

		if !foundParam {
			if strings.HasPrefix(trimmed, paramName+":") {
				foundParam = true
				paramIndent = ind
			}
			continue
		}

		if ind <= paramIndent {
			break
		}

		if strings.HasPrefix(trimmed, attrName+":") {
			colonIdx := strings.Index(line, ":")
			if colonIdx < 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: 0},
					End:   protocol.Position{Line: i, Character: len(line)},
				}
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: valStart},
				End:   protocol.Position{Line: i, Character: len(line)},
			}
		}
	}

	return findParameterRangeYAML(content, paramName)
}

func findResourceRangeYAML(content, resName string) protocol.Range {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, resName+":") {
			col := strings.Index(line, resName)
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: col},
				End:   protocol.Position{Line: i, Character: col + len(resName)},
			}
		}
	}
	return protocol.Range{}
}

func findResourceTypeRangeYAML(content, resName string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundResource := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, resName+":") {
			foundResource = true
			continue
		}
		if foundResource && strings.HasPrefix(trimmed, "Type:") {
			idx := strings.Index(line, ":")
			if idx < 0 {
				break
			}
			valStart := idx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			valEnd := valStart
			for valEnd < len(line) && line[valEnd] != ' ' && line[valEnd] != '\t' && line[valEnd] != '#' {
				valEnd++
			}
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: valStart},
				End:   protocol.Position{Line: i, Character: valEnd},
			}
		}
		if foundResource && countIndent(line) == 0 && trimmed != "" {
			break
		}
	}
	return findResourceRangeYAML(content, resName)
}

func findResourcePropertyValueRangeYAML(content, resName, propName string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundResource := false
	inProperties := false
	resIndent := -1
	propsIndent := -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := countIndent(line)

		if !foundResource {
			if strings.HasPrefix(trimmed, resName+":") {
				foundResource = true
				resIndent = ind
			}
			continue
		}

		if ind <= resIndent && trimmed != "" {
			break
		}

		if !inProperties {
			if strings.HasPrefix(trimmed, "Properties:") || trimmed == "Properties" {
				inProperties = true
				propsIndent = ind
			}
			continue
		}

		if ind <= propsIndent {
			break
		}

		if strings.HasPrefix(trimmed, propName+":") {
			colonIdx := strings.Index(line, ":")
			if colonIdx < 0 {
				continue
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			if valStart < len(line) {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: valStart},
					End:   protocol.Position{Line: i, Character: len(line)},
				}
			}
			propIndent := ind
			for j := i + 1; j < len(lines); j++ {
				jTrimmed := strings.TrimSpace(lines[j])
				if jTrimmed == "" || strings.HasPrefix(jTrimmed, "#") {
					continue
				}
				jInd := countIndent(lines[j])
				if jInd <= propIndent {
					break
				}
				return protocol.Range{
					Start: protocol.Position{Line: j, Character: jInd},
					End:   protocol.Position{Line: j, Character: len(lines[j])},
				}
			}
		}
	}

	return findResourceRangeYAML(content, resName)
}

func findLocalsRangeYAML(content, localName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inLocals := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		ind := countIndent(line)
		if ind == 0 {
			inLocals = strings.HasPrefix(trimmed, "Locals:") || trimmed == "Locals"
			continue
		}
		if inLocals && strings.HasPrefix(trimmed, localName+":") {
			col := strings.Index(line, localName)
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: col},
				End:   protocol.Position{Line: i, Character: col + len(localName)},
			}
		}
	}
	return protocol.Range{}
}

func findMappingsRangeYAML(content, mapName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inMappings := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		ind := countIndent(line)
		if ind == 0 {
			inMappings = strings.HasPrefix(trimmed, "Mappings:") || trimmed == "Mappings"
			continue
		}
		if inMappings && strings.HasPrefix(trimmed, mapName+":") {
			col := strings.Index(line, mapName)
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: col},
				End:   protocol.Position{Line: i, Character: col + len(mapName)},
			}
		}
	}
	return protocol.Range{}
}

func findConditionsRangeYAML(content, condName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inConditions := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		ind := countIndent(line)
		if ind == 0 {
			inConditions = strings.HasPrefix(trimmed, "Conditions:") || trimmed == "Conditions"
			continue
		}
		if inConditions && strings.HasPrefix(trimmed, condName+":") {
			col := strings.Index(line, condName)
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: col},
				End:   protocol.Position{Line: i, Character: col + len(condName)},
			}
		}
	}
	return protocol.Range{}
}

func findConditionValueRangeYAML(content, section, entryName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inSection := false
	foundEntry := false
	entryIndent := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		ind := countIndent(line)

		if ind == 0 {
			if foundEntry {
				break
			}
			inSection = strings.HasPrefix(trimmed, section+":") || trimmed == section
			continue
		}

		if !inSection {
			continue
		}

		if !foundEntry {
			if strings.HasPrefix(trimmed, entryName+":") {
				foundEntry = true
				entryIndent = ind
			}
			continue
		}

		if ind <= entryIndent {
			break
		}

		if strings.HasPrefix(trimmed, "Condition:") {
			colonIdx := strings.Index(line, ":")
			if colonIdx < 0 {
				continue
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: valStart},
				End:   protocol.Position{Line: i, Character: len(trimmed) + ind},
			}
		}
	}

	return protocol.Range{}
}

// findYAMLKeySepColon returns the index of the YAML key-value separator colon.
// In YAML, a colon is a key-value separator only when followed by a space/tab
// or at the end of the string. Colons inside keys (e.g. ALIYUN::ROS::Interface)
// are not separators.
func findYAMLKeySepColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i == len(s)-1 || s[i+1] == ' ' || s[i+1] == '\t') {
			return i
		}
	}
	return -1
}

// --- YAML-specific validation ---

func validateDuplicateKeys(ctx ValidationContext) []protocol.Diagnostic {
	lines := strings.Split(ctx.Content, "\n")
	var diags []protocol.Diagnostic

	type scope struct {
		indent int
		keys   map[string]int
	}
	var stack []*scope

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "---") {
			continue
		}

		indent := countIndent(line)

		colonIdx := findYAMLKeySepColon(trimmed)
		if colonIdx <= 0 {
			continue
		}

		key := trimmed[:colonIdx]
		isListItem := false
		if strings.HasPrefix(key, "- ") {
			key = strings.TrimSpace(strings.TrimPrefix(key, "- "))
			isListItem = true
		}
		if key == "" || key == "-" {
			continue
		}

		for len(stack) > 0 && stack[len(stack)-1].indent > indent {
			stack = stack[:len(stack)-1]
		}

		if isListItem {
			effectiveIndent := indent + 2
			for len(stack) > 0 && stack[len(stack)-1].indent >= effectiveIndent {
				stack = stack[:len(stack)-1]
			}
			s := &scope{indent: effectiveIndent, keys: map[string]int{key: i}}
			stack = append(stack, s)
			continue
		}

		if len(stack) > 0 && stack[len(stack)-1].indent == indent {
			s := stack[len(stack)-1]
			if firstLine, ok := s.keys[key]; ok {
				col := indent
				tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.DuplicateKey })
				if tmpl == "" {
					tmpl = "Duplicate key %q (first defined at line %d)"
				}
				diags = append(diags, protocol.Diagnostic{
					Range: protocol.Range{
						Start: protocol.Position{Line: i, Character: col},
						End:   protocol.Position{Line: i, Character: col + len(key)},
					},
					Severity: protocol.DiagnosticSeverityWarning,
					Source:   "ros-lsp",
					Message:  fmt.Sprintf(tmpl, key, firstLine+1),
				})
			} else {
				s.keys[key] = i
			}
		} else {
			s := &scope{indent: indent, keys: map[string]int{key: i}}
			stack = append(stack, s)
		}
	}

	return diags
}
