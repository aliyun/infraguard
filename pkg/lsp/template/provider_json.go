package template

import (
	"fmt"
	"strings"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
)

type jsonFormatHandler struct{}

func (h *jsonFormatHandler) ParseTemplate(content string) *ParsedTemplate {
	return ParseJSON(content)
}

func (h *jsonFormatHandler) BuildTopLevelSnippet(item *protocol.CompletionItem, blockName string, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	indentStep := DetectIndentStep(lines, ctx.Line)
	s1 := strings.Repeat(" ", indentStep)
	s2 := strings.Repeat(" ", 2*indentStep)

	var newTextInner string
	isSnippet := true
	switch blockName {
	case "ROSTemplateFormatVersion":
		newTextInner = `ROSTemplateFormatVersion": "2015-09-01"`
		isSnippet = false
	case "Description":
		newTextInner = `Description": "$0"`
	case "Parameters":
		newTextInner = fmt.Sprintf("Parameters\": {\n%s\"${1:ParameterName}\": {\n%s\"Type\": \"$0\"\n%s}\n}", s1, s2, s1)
	case "Locals":
		newTextInner = fmt.Sprintf("Locals\": {\n%s\"${1:LocalName}\": {\n%s\"Value\": $0\n%s}\n}", s1, s2, s1)
	case "Resources":
		newTextInner = fmt.Sprintf("Resources\": {\n%s\"${1:LogicalId}\": {\n%s\"Type\": \"$0\"\n%s}\n}", s1, s2, s1)
	case "Outputs":
		newTextInner = fmt.Sprintf("Outputs\": {\n%s\"${1:OutputName}\": {\n%s\"Value\": \"$0\"\n%s}\n}", s1, s2, s1)
	case "Conditions":
		newTextInner = fmt.Sprintf("Conditions\": {\n%s\"${1:ConditionName}\": {\n%s\"Fn::Equals\": [\"${2:value1}\", \"${0:value2}\"]\n%s}\n}", s1, s2, s1)
	case "Mappings":
		s3 := strings.Repeat(" ", 3*indentStep)
		newTextInner = fmt.Sprintf("Mappings\": {\n%s\"${1:MapName}\": {\n%s\"${2:FirstKey}\": {\n%s\"${3:SecondKey}\": \"${0:Value}\"\n%s}\n%s}\n}", s1, s2, s3, s2, s1)
	default:
		newTextInner = fmt.Sprintf("%s\": {\n%s$0\n}", blockName, s1)
	}

	if isSnippet {
		item.InsertTextFormat = protocol.InsertTextFormatSnippet
	}
	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
		item.FilterText = blockName
	} else {
		item.InsertText = `"` + newTextInner
	}
}

func (h *jsonFormatHandler) BuildTypeCompletion(item *protocol.CompletionItem, name string, analysis *AnalysisContext, ctx CompletionContext, lines []string, hasProps bool) {
	lineText := lines[ctx.Line]
	endCol, hasClosingQuote, hasComma := FindJSONValueEnd(lineText, analysis.ValueStartCol)

	var required []string
	if !hasProps {
		required = ctx.Registry.RequiredProperties(name)
	}

	if len(required) > 0 {
		indentStep := DetectIndentStep(lines, ctx.Line)
		propRelativeIndent := strings.Repeat(" ", indentStep)

		newText := name + `",`
		newText += "\n" + `"Properties": {`
		for j, prop := range required {
			if j > 0 {
				newText += ","
			}
			newText += "\n" + propRelativeIndent + `"` + prop + `": "${` + fmt.Sprintf("%d", j+1) + `}"`
		}
		newText += "\n}"

		item.InsertTextFormat = protocol.InsertTextFormatSnippet
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newText,
		}
	} else {
		newText := name
		if hasClosingQuote {
			newText += `"`
			if hasComma {
				newText += ","
			}
		}

		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newText,
		}
	}
}

func (h *jsonFormatHandler) BuildPropertyCompletion(item *protocol.CompletionItem, name string, ctx CompletionContext) {
	newTextInner := name + `": "$0"`
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
		item.FilterText = name
	} else {
		item.InsertText = `"` + newTextInner
	}
}

func (h *jsonFormatHandler) BuildOutputBlockSnippet(item *protocol.CompletionItem, blockName string, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	trimmed := strings.TrimSpace(lineText)

	item.InsertTextFormat = protocol.InsertTextFormatSnippet

	// Check if cursor is on the output name line (e.g., "OutputName":|)
	key := extractJSONKey(trimmed)
	colonIdx := strings.Index(trimmed, ":")
	onParentLine := key != "" && !isOutputBlockKey(key) && colonIdx >= 0

	if onParentLine {
		// VS Code auto-adds the base indent of the current line to subsequent
		// snippet lines, so we only use relative indentation (the indent step).
		indentStep := DetectIndentStep(lines, ctx.Line)
		s1 := strings.Repeat(" ", indentStep)

		var snippet string
		switch blockName {
		case "Value":
			snippet = fmt.Sprintf(" {\n%s\"Value\": $0\n}", s1)
		case "Description":
			snippet = fmt.Sprintf(" {\n%s\"Description\": \"$0\"\n}", s1)
		case "Condition":
			snippet = fmt.Sprintf(" {\n%s\"Condition\": \"$0\"\n}", s1)
		default:
			snippet = fmt.Sprintf(" {\n%s\"%s\": $0\n}", s1, blockName)
		}
		item.InsertText = snippet
	} else {
		var newTextInner string
		switch blockName {
		case "Value":
			newTextInner = `Value": $0`
		case "Description":
			newTextInner = `Description": "$0"`
		case "Condition":
			newTextInner = `Condition": "$0"`
		default:
			newTextInner = blockName + `": $0`
		}

		startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
		if found {
			item.TextEdit = &protocol.TextEdit{
				Range: protocol.Range{
					Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
					End:   protocol.Position{Line: ctx.Line, Character: endCol},
				},
				NewText: newTextInner,
			}
			item.FilterText = blockName
		} else {
			item.InsertText = `"` + newTextInner
		}
	}

	if blockName == "Value" {
		item.Command = &protocol.Command{
			Title:   "Trigger Suggest",
			Command: "editor.action.triggerSuggest",
		}
	}
}

func (h *jsonFormatHandler) BuildResourceBlockSnippet(item *protocol.CompletionItem, blockName string, analysis *AnalysisContext, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	indentStep := DetectIndentStep(lines, ctx.Line)
	s1 := strings.Repeat(" ", indentStep)

	var newTextInner string
	switch blockName {
	case "Type":
		newTextInner = `Type": "$0"`
	case "Properties":
		newTextInner = buildJSONPropertiesSnippet(analysis.ResourceTypeName, ctx.Registry, indentStep)
	case "Metadata":
		newTextInner = fmt.Sprintf("Metadata\": {\n%s$0\n}", s1)
	case "DependsOn":
		newTextInner = `DependsOn": [$0]`
	case "DeletionPolicy":
		newTextInner = `DeletionPolicy": "$0"`
	case "Condition":
		newTextInner = `Condition": "$0"`
	case "Count":
		newTextInner = `Count": $0`
	default:
		newTextInner = blockName + `": $0`
	}

	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
		item.FilterText = blockName
	} else {
		item.InsertText = `"` + newTextInner
	}
}

func buildJSONPropertiesSnippet(resourceType string, registry *schema.Registry, indentStep int) string {
	s1 := strings.Repeat(" ", indentStep)
	if resourceType == "" || registry == nil {
		return fmt.Sprintf("Properties\": {\n%s$0\n}", s1)
	}
	required := registry.RequiredProperties(resourceType)
	if len(required) == 0 {
		return fmt.Sprintf("Properties\": {\n%s$0\n}", s1)
	}
	snippet := "Properties\": {"
	for i, prop := range required {
		comma := ","
		if i == len(required)-1 {
			comma = ""
		}
		snippet += fmt.Sprintf("\n%s\"%s\": \"$%d\"%s", s1, prop, i+1, comma)
	}
	snippet += "\n}"
	return snippet
}

func (h *jsonFormatHandler) BuildLocalsPropertySnippet(item *protocol.CompletionItem, prop ROSLocalsProperty, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	indentStep := DetectIndentStep(lines, ctx.Line)
	s1 := strings.Repeat(" ", indentStep)

	var newTextInner string
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	switch prop.Name {
	case "Properties":
		newTextInner = fmt.Sprintf("Properties\": {\n%s$0\n}", s1)
	case "Type":
		newTextInner = `Type": "$0"`
	default:
		newTextInner = prop.Name + `": $0`
	}

	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
		item.FilterText = prop.Name
	} else {
		item.InsertText = `"` + newTextInner
	}
}

func (h *jsonFormatHandler) BuildLocalsTypeValueSnippet(item *protocol.CompletionItem, typeName string, analysis *AnalysisContext, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	endCol, hasClosingQuote, hasComma := FindJSONValueEnd(lineText, analysis.ValueStartCol)

	newText := typeName
	if hasClosingQuote {
		newText += `"`
		if hasComma {
			newText += ","
		}
	}
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: endCol},
		},
		NewText: newText,
	}
}

func (h *jsonFormatHandler) BuildParameterPropertySnippet(item *protocol.CompletionItem, prop ROSParameterProperty, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	indentStep := DetectIndentStep(lines, ctx.Line)
	s1 := strings.Repeat(" ", indentStep)

	var newTextInner string
	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	switch prop.Name {
	case "AllowedValues":
		newTextInner = fmt.Sprintf("AllowedValues\": [\n%s$0\n]", s1)
	case "Description":
		newTextInner = fmt.Sprintf("Description\": {\n%s\"en\": \"${1:Description}\",\n%s\"zh-cn\": \"${2:描述}\"\n}", s1, s1)
	case "ConstraintDescription":
		newTextInner = fmt.Sprintf("ConstraintDescription\": {\n%s\"en\": \"${1:ConstraintDescription}\",\n%s\"zh-cn\": \"${2:约束描述}\"\n}", s1, s1)
	case "Label":
		newTextInner = fmt.Sprintf("Label\": {\n%s\"en\": \"${1:Label}\",\n%s\"zh-cn\": \"${2:标签}\"\n}", s1, s1)
	case "Placeholder":
		newTextInner = fmt.Sprintf("Placeholder\": {\n%s\"en\": \"${1:Placeholder}\",\n%s\"zh-cn\": \"${2:占位}\"\n}", s1, s1)
	case "AssociationPropertyMetadata":
		newTextInner = fmt.Sprintf("AssociationPropertyMetadata\": {\n%s$0\n}", s1)
	case "Type":
		newTextInner = `Type": "$0"`
	default:
		newTextInner = prop.Name + `": "$0"`
	}

	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
		item.FilterText = prop.Name
	} else {
		item.InsertText = `"` + newTextInner
	}
}

func (h *jsonFormatHandler) BuildParameterTypeValueSnippet(item *protocol.CompletionItem, typeName string, analysis *AnalysisContext, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	endCol, hasClosingQuote, hasComma := FindJSONValueEnd(lineText, analysis.ValueStartCol)

	newText := typeName
	if hasClosingQuote {
		newText += `"`
		if hasComma {
			newText += ","
		}
	}
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: endCol},
		},
		NewText: newText,
	}
}

func (h *jsonFormatHandler) BuildAssociationPropertyValueSnippet(item *protocol.CompletionItem, name string, analysis *AnalysisContext, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]
	endCol, hasClosingQuote, hasComma := FindJSONValueEnd(lineText, analysis.ValueStartCol)

	newText := name
	if hasClosingQuote {
		newText += `"`
		if hasComma {
			newText += ","
		}
	}
	item.TextEdit = &protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: ctx.Line, Character: analysis.ValueStartCol},
			End:   protocol.Position{Line: ctx.Line, Character: endCol},
		},
		NewText: newText,
	}
}

func (h *jsonFormatHandler) BuildAssociationPropertyMetadataKeySnippet(item *protocol.CompletionItem, key string, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]

	newTextInner := key + `": "$0"`

	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
	} else {
		item.InsertText = `"` + newTextInner
	}
}

func (h *jsonFormatHandler) BuildIntrinsicFunctionSnippet(item *protocol.CompletionItem, fn IntrinsicFunction, _ bool, ctx CompletionContext) {
	lines := strings.Split(ctx.Content, "\n")
	lineText := lines[ctx.Line]

	newTextInner := fn.Name + `": "$0"`

	item.InsertTextFormat = protocol.InsertTextFormatSnippet
	startCol, endCol, found := FindJSONKeyEditRange(lineText, ctx.Col)
	if found {
		item.TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: ctx.Line, Character: startCol + 1},
				End:   protocol.Position{Line: ctx.Line, Character: endCol},
			},
			NewText: newTextInner,
		}
		item.FilterText = fn.Name
	} else {
		item.InsertText = `"` + newTextInner
	}
	item.Command = &protocol.Command{
		Title:   "Trigger Suggest",
		Command: "editor.action.triggerSuggest",
	}
}

func (h *jsonFormatHandler) HasShortTags() bool {
	return false
}

func (h *jsonFormatHandler) FindKeyLine(content, key string) int {
	return FindKeyLineInJSON(content, key)
}

func (h *jsonFormatHandler) FindParameterRange(content, paramName string) protocol.Range {
	return findParameterRangeJSON(content, paramName)
}

func (h *jsonFormatHandler) FindParameterAttrValueRange(content, paramName, attrName string) protocol.Range {
	return findParameterAttrValueRangeJSON(content, paramName, attrName)
}

func (h *jsonFormatHandler) FindLocalsRange(content, localName string) protocol.Range {
	return findLocalsRangeJSON(content, localName)
}

func (h *jsonFormatHandler) FindResourceRange(content, resName string) protocol.Range {
	return findResourceRangeJSON(content, resName)
}

func (h *jsonFormatHandler) FindResourceTypeRange(content, resName string) protocol.Range {
	return findResourceTypeRangeJSON(content, resName)
}

func (h *jsonFormatHandler) FindResourcePropertyValueRange(content, resName, propName string) protocol.Range {
	return findResourcePropertyValueRangeJSON(content, resName, propName)
}

func (h *jsonFormatHandler) FindMappingsRange(content, mapName string) protocol.Range {
	return findMappingsRangeJSON(content, mapName)
}

func (h *jsonFormatHandler) FindConditionsRange(content, condName string) protocol.Range {
	return findConditionsRangeJSON(content, condName)
}

func (h *jsonFormatHandler) FindConditionValueRange(content, section, entryName string) protocol.Range {
	return findConditionValueRangeJSON(content, section, entryName)
}

func (h *jsonFormatHandler) FindAssociationPropertyMetadataKeyRange(content, paramName, metaKey string) protocol.Range {
	return findAssociationPropertyMetadataKeyRangeJSON(content, paramName, metaKey)
}

func (h *jsonFormatHandler) FindParamRefInMetadataRange(content, paramName, refName string) protocol.Range {
	return findParamRefInMetadataRangeJSON(content, paramName, refName)
}

func (h *jsonFormatHandler) FindRefValueRange(content, refName string) protocol.Range {
	return findRefValueRangeJSON(content, refName)
}

func (h *jsonFormatHandler) FindGetAttResourceRange(content, resourceName string) protocol.Range {
	return findGetAttResourceRangeJSON(content, resourceName)
}

func (h *jsonFormatHandler) FindGetAttAttributeRange(content, resourceName, attrName string) protocol.Range {
	return findGetAttAttributeRangeJSON(content, resourceName, attrName)
}

func (h *jsonFormatHandler) ExtractKeyFromLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		end := strings.Index(trimmed[1:], `"`)
		if end >= 0 {
			return trimmed[1 : end+1]
		}
	}
	return strings.Trim(strings.SplitN(trimmed, ":", 2)[0], `" `)
}

func (h *jsonFormatHandler) ExtractValueFromLine(line string) string {
	trimmed := strings.TrimSpace(line)
	colonIdx := -1
	inQuote := false
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == '"' {
			inQuote = !inQuote
		}
		if trimmed[i] == ':' && !inQuote {
			colonIdx = i
			break
		}
	}
	if colonIdx < 0 {
		return ""
	}
	val := strings.TrimSpace(trimmed[colonIdx+1:])
	val = strings.TrimRight(val, ",")
	return strings.Trim(val, `"`)
}

func (h *jsonFormatHandler) ValidateFormat(ctx ValidationContext) []protocol.Diagnostic {
	return nil
}

// --- JSON-specific range finding ---

func findParameterRangeJSON(content, paramName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inParameters := false
	needle := `"` + paramName + `"`
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"Parameters"`) && strings.Contains(trimmed, ":") {
			inParameters = true
			continue
		}
		if inParameters && strings.Contains(trimmed, needle) {
			col := strings.Index(line, needle)
			if col >= 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: col},
					End:   protocol.Position{Line: i, Character: col + len(needle)},
				}
			}
		}
	}
	return protocol.Range{}
}

// findAssociationPropertyMetadataKeyRangeJSON finds the range of a specific key
// inside the AssociationPropertyMetadata block of a named parameter in JSON.
func findAssociationPropertyMetadataKeyRangeJSON(content, paramName, metaKey string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundParam := false
	braceDepth := 0
	inMeta := false
	metaBraceDepth := 0
	metaKeyNeedle := `"` + metaKey + `"`

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !foundParam {
			if strings.Contains(trimmed, `"`+paramName+`"`) {
				foundParam = true
				braceDepth = 0
			}
			continue
		}

		braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")

		if braceDepth < 0 {
			break
		}

		if !inMeta {
			if strings.Contains(trimmed, `"AssociationPropertyMetadata"`) && strings.Contains(trimmed, ":") {
				inMeta = true
				metaBraceDepth = braceDepth
			}
			continue
		}

		if braceDepth < metaBraceDepth {
			break
		}

		if strings.Contains(trimmed, metaKeyNeedle) && strings.Contains(trimmed, ":") {
			col := strings.Index(line, metaKeyNeedle)
			if col >= 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: col + 1},
					End:   protocol.Position{Line: i, Character: col + 1 + len(metaKey)},
				}
			}
		}
	}
	return findParameterAttrValueRangeJSON(content, paramName, "AssociationPropertyMetadata")
}

// findParamRefInMetadataRangeJSON finds the range of ${refName} within the
// AssociationPropertyMetadata block of a named parameter in JSON.
func findParamRefInMetadataRangeJSON(content, paramName, refName string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundParam := false
	braceDepth := 0
	inMeta := false
	metaBraceDepth := 0
	needle := "${" + refName + "}"

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !foundParam {
			if strings.Contains(trimmed, `"`+paramName+`"`) {
				foundParam = true
				braceDepth = 0
			}
			continue
		}

		braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")

		if braceDepth < 0 {
			break
		}

		if !inMeta {
			if strings.Contains(trimmed, `"AssociationPropertyMetadata"`) && strings.Contains(trimmed, ":") {
				inMeta = true
				metaBraceDepth = braceDepth
			}
			continue
		}

		if braceDepth < metaBraceDepth {
			break
		}

		col := strings.Index(line, needle)
		if col >= 0 {
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: col},
				End:   protocol.Position{Line: i, Character: col + len(needle)},
			}
		}
	}
	return findAssociationPropertyMetadataKeyRangeJSON(content, paramName, "AssociationPropertyMetadata")
}

func findParameterAttrValueRangeJSON(content, paramName, attrName string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundParam := false
	braceDepth := 0
	attrNeedle := `"` + attrName + `"`

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !foundParam {
			if strings.Contains(trimmed, `"`+paramName+`"`) {
				foundParam = true
				braceDepth = 0
			}
			continue
		}

		braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")

		if braceDepth < 0 {
			break
		}

		if strings.Contains(trimmed, attrNeedle) && strings.Contains(trimmed, ":") {
			colonIdx := strings.Index(line, ":")
			if colonIdx < 0 {
				continue
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			valEnd := len(line)
			for valEnd > valStart && (line[valEnd-1] == ',' || line[valEnd-1] == ' ' || line[valEnd-1] == '\t') {
				valEnd--
			}
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: valStart},
				End:   protocol.Position{Line: i, Character: valEnd},
			}
		}
	}

	return findParameterRangeJSON(content, paramName)
}

func findResourceRangeJSON(content, resName string) protocol.Range {
	lines := strings.Split(content, "\n")
	needle := `"` + resName + `"`
	for i, line := range lines {
		if strings.Contains(line, needle) {
			col := strings.Index(line, needle)
			if col >= 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: col},
					End:   protocol.Position{Line: i, Character: col + len(needle)},
				}
			}
		}
	}
	return protocol.Range{}
}

func findResourceTypeRangeJSON(content, resName string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundResource := false
	needle := `"` + resName + `"`
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !foundResource {
			if strings.Contains(trimmed, needle) {
				foundResource = true
			}
			continue
		}
		if strings.Contains(trimmed, `"Type"`) && strings.Contains(trimmed, ":") {
			colonIdx := strings.Index(line, ":")
			if colonIdx < 0 {
				break
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			if valStart < len(line) && line[valStart] == '"' {
				valStart++
			}
			valEnd := valStart
			for valEnd < len(line) && line[valEnd] != '"' && line[valEnd] != ',' {
				valEnd++
			}
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: valStart},
				End:   protocol.Position{Line: i, Character: valEnd},
			}
		}
		if strings.Contains(trimmed, "}") && !strings.Contains(trimmed, "{") && !strings.Contains(trimmed, `"`) {
			break
		}
	}
	return findResourceRangeJSON(content, resName)
}

func findResourcePropertyValueRangeJSON(content, resName, propName string) protocol.Range {
	lines := strings.Split(content, "\n")
	resNeedle := `"` + resName + `"`
	propNeedle := `"` + propName + `"`
	foundResource := false
	foundProperties := false
	braceDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !foundResource {
			if strings.Contains(trimmed, resNeedle) {
				foundResource = true
				braceDepth = 0
			}
			continue
		}

		if !foundProperties {
			if strings.Contains(trimmed, `"Properties"`) && strings.Contains(trimmed, ":") {
				foundProperties = true
				braceDepth = 0
			}
			braces := strings.Count(trimmed, "}") - strings.Count(trimmed, "{")
			if braces > 0 && !foundProperties {
				break
			}
			continue
		}

		braceDepth += strings.Count(trimmed, "{") + strings.Count(trimmed, "[") -
			strings.Count(trimmed, "}") - strings.Count(trimmed, "]")

		if braceDepth < 0 {
			break
		}

		if strings.Contains(trimmed, propNeedle) && strings.Contains(trimmed, ":") {
			colonIdx := -1
			inQuote := false
			for ci := 0; ci < len(line); ci++ {
				if line[ci] == '"' {
					inQuote = !inQuote
				}
				if line[ci] == ':' && !inQuote {
					colonIdx = ci
					break
				}
			}
			if colonIdx < 0 {
				continue
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			valEnd := len(line)
			for valEnd > valStart && (line[valEnd-1] == ',' || line[valEnd-1] == ' ' || line[valEnd-1] == '\t') {
				valEnd--
			}
			if valStart < valEnd {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: valStart},
					End:   protocol.Position{Line: i, Character: valEnd},
				}
			}
		}
	}

	return findResourceRangeJSON(content, resName)
}

func findMappingsRangeJSON(content, mapName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inMappings := false
	needle := `"` + mapName + `"`
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"Mappings"`) && strings.Contains(trimmed, ":") {
			inMappings = true
			continue
		}
		if inMappings && strings.Contains(trimmed, needle) {
			col := strings.Index(line, needle)
			if col >= 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: col},
					End:   protocol.Position{Line: i, Character: col + len(needle)},
				}
			}
		}
	}
	return protocol.Range{}
}

func findConditionsRangeJSON(content, condName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inConditions := false
	needle := `"` + condName + `"`
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"Conditions"`) && strings.Contains(trimmed, ":") {
			inConditions = true
			continue
		}
		if inConditions && strings.Contains(trimmed, needle) {
			col := strings.Index(line, needle)
			if col >= 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: col},
					End:   protocol.Position{Line: i, Character: col + len(needle)},
				}
			}
		}
	}
	return protocol.Range{}
}

func findConditionValueRangeJSON(content, section, entryName string) protocol.Range {
	lines := strings.Split(content, "\n")
	foundEntry := false
	braceDepth := 0
	condNeedle := `"Condition"`

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !foundEntry {
			if strings.Contains(trimmed, `"`+entryName+`"`) {
				foundEntry = true
				braceDepth = 0
			}
			continue
		}

		braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")

		if braceDepth < 0 {
			break
		}

		if strings.Contains(trimmed, condNeedle) && strings.Contains(trimmed, ":") {
			colonIdx := -1
			inQuote := false
			for ci := 0; ci < len(line); ci++ {
				if line[ci] == '"' {
					inQuote = !inQuote
				}
				if line[ci] == ':' && !inQuote {
					colonIdx = ci
					break
				}
			}
			if colonIdx < 0 {
				continue
			}
			valStart := colonIdx + 1
			for valStart < len(line) && (line[valStart] == ' ' || line[valStart] == '\t') {
				valStart++
			}
			valEnd := len(line)
			for valEnd > valStart && (line[valEnd-1] == ',' || line[valEnd-1] == ' ' || line[valEnd-1] == '\t') {
				valEnd--
			}
			return protocol.Range{
				Start: protocol.Position{Line: i, Character: valStart},
				End:   protocol.Position{Line: i, Character: valEnd},
			}
		}
	}

	return protocol.Range{}
}

func findLocalsRangeJSON(content, localName string) protocol.Range {
	lines := strings.Split(content, "\n")
	inLocals := false
	needle := `"` + localName + `"`
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"Locals"`) && strings.Contains(trimmed, ":") {
			inLocals = true
			continue
		}
		if inLocals && strings.Contains(trimmed, needle) {
			col := strings.Index(line, needle)
			if col >= 0 {
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: col},
					End:   protocol.Position{Line: i, Character: col + len(needle)},
				}
			}
		}
	}
	return protocol.Range{}
}

func findRefValueRangeJSON(content, refName string) protocol.Range {
	lines := strings.Split(content, "\n")
	quoted := `"` + refName + `"`
	for i, line := range lines {
		if strings.Contains(line, `"Ref"`) {
			refKeyIdx := strings.Index(line, `"Ref"`)
			idx := strings.Index(line[refKeyIdx:], quoted)
			if idx >= 0 {
				absIdx := refKeyIdx + idx
				return protocol.Range{
					Start: protocol.Position{Line: i, Character: absIdx + 1},
					End:   protocol.Position{Line: i, Character: absIdx + 1 + len(refName)},
				}
			}
		}
	}
	return protocol.Range{}
}

func findGetAttResourceRangeJSON(content, resourceName string) protocol.Range {
	lines := strings.Split(content, "\n")
	quoted := `"` + resourceName + `"`
	for i, line := range lines {
		if strings.Contains(line, `"Fn::GetAtt"`) {
			bracketIdx := strings.Index(line, "[")
			if bracketIdx >= 0 {
				idx := strings.Index(line[bracketIdx:], quoted)
				if idx >= 0 {
					absIdx := bracketIdx + idx
					return protocol.Range{
						Start: protocol.Position{Line: i, Character: absIdx + 1},
						End:   protocol.Position{Line: i, Character: absIdx + 1 + len(resourceName)},
					}
				}
			}
		}
		// Multiline: resource name on its own line after Fn::GetAtt
		if strings.Contains(line, quoted) {
			for j := i - 1; j >= 0; j-- {
				lt := strings.TrimSpace(lines[j])
				if strings.Contains(lt, `"Fn::GetAtt"`) {
					itemsBefore := 0
					for k := j + 1; k < i; k++ {
						kt := strings.TrimSpace(lines[k])
						if strings.Contains(kt, `"`) && kt != "[" && kt != "]" {
							itemsBefore++
						}
					}
					if itemsBefore == 0 {
						idx := strings.Index(line, quoted)
						if idx >= 0 {
							return protocol.Range{
								Start: protocol.Position{Line: i, Character: idx + 1},
								End:   protocol.Position{Line: i, Character: idx + 1 + len(resourceName)},
							}
						}
					}
					break
				}
				if strings.ContainsAny(lt, "{}") && !strings.Contains(lt, "[") {
					break
				}
			}
		}
	}
	return protocol.Range{}
}

func findGetAttAttributeRangeJSON(content, resourceName, attrName string) protocol.Range {
	lines := strings.Split(content, "\n")
	quotedRes := `"` + resourceName + `"`
	quotedAttr := `"` + attrName + `"`
	for i, line := range lines {
		// Inline: "Fn::GetAtt": ["Resource", "Attribute"]
		if strings.Contains(line, `"Fn::GetAtt"`) {
			bracketIdx := strings.Index(line, "[")
			if bracketIdx >= 0 {
				elements, positions := extractJSONArrayElements(line[bracketIdx+1:], bracketIdx+1)
				if len(elements) >= 2 && len(positions) >= 2 && elements[0] == resourceName && elements[1] == attrName {
					pos := positions[1]
					return protocol.Range{
						Start: protocol.Position{Line: i, Character: pos.start},
						End:   protocol.Position{Line: i, Character: pos.start + len(attrName)},
					}
				}
			}
		}
		// Multiline: attribute on its own line after resource
		if strings.Contains(line, quotedAttr) {
			for j := i - 1; j >= 0; j-- {
				lt := strings.TrimSpace(lines[j])
				if strings.Contains(lt, quotedRes) {
					// Verify this is under a Fn::GetAtt
					for k := j - 1; k >= 0; k-- {
						kt := strings.TrimSpace(lines[k])
						if strings.Contains(kt, `"Fn::GetAtt"`) {
							idx := strings.Index(line, quotedAttr)
							if idx >= 0 {
								return protocol.Range{
									Start: protocol.Position{Line: i, Character: idx + 1},
									End:   protocol.Position{Line: i, Character: idx + 1 + len(attrName)},
								}
							}
							break
						}
						if strings.ContainsAny(kt, "{}") && !strings.Contains(kt, "[") {
							break
						}
					}
					break
				}
				if strings.Contains(lt, `"Fn::GetAtt"`) || (strings.ContainsAny(lt, "{}") && !strings.Contains(lt, "[")) {
					break
				}
			}
		}
	}
	return protocol.Range{}
}
