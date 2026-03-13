package template

import (
	"strings"
)

func analyzeJSONPosition(content string, line, col int) *AnalysisContext {
	lines := strings.Split(content, "\n")
	if line < 0 || line >= len(lines) {
		return &AnalysisContext{Type: ContextUnknown}
	}

	currentLine := lines[line]

	// Check intrinsic function contexts first (highest priority, like YAML)
	if ctx := checkJSONConditionFnContext(lines, line, col); ctx != nil {
		return ctx
	}
	if ctx := checkJSONFindInMapContext(lines, line, col); ctx != nil {
		return ctx
	}
	if ctx := checkJSONRefContext(lines, line, col); ctx != nil {
		return ctx
	}
	if ctx := checkJSONGetAttContext(lines, line, col); ctx != nil {
		return ctx
	}

	section := findJSONSection(lines, line)

	if section == "Parameters" {
		if ctx := checkJSONParameterTypeContext(lines, line, col); ctx != nil {
			return ctx
		}
		if ctx := checkJSONAssociationPropertyContext(lines, line, col); ctx != nil {
			return ctx
		}
		if ctx := checkJSONAssociationPropertyMetadataContext(lines, line, col); ctx != nil {
			return ctx
		}
		depth := 0
		for i := 0; i <= line; i++ {
			trimmed := strings.TrimSpace(lines[i])
			depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		}
		if depth >= 3 {
			paramName := findParameterNameJSON(lines, line)
			return &AnalysisContext{
				Type:         ContextParameterProperties,
				ResourceName: paramName,
				Prefix:       extractJSONKeyPrefix(currentLine, col),
				ExistingKeys: findExistingParameterAttrsJSON(lines, line),
			}
		}
	}

	if section == "Locals" {
		if ctx := checkJSONLocalsContext(lines, line, col); ctx != nil {
			return ctx
		}
		return &AnalysisContext{Type: ContextUnknown}
	}

	if section == "Outputs" {
		if ctx := checkJSONOutputContext(lines, line, col); ctx != nil {
			return ctx
		}
		return &AnalysisContext{Type: ContextUnknown}
	}

	if section == "Mappings" {
		return &AnalysisContext{Type: ContextMappingsBlock}
	}

	if section == "Conditions" {
		return &AnalysisContext{
			Type:   ContextConditionsBlock,
			Prefix: extractJSONKeyPrefix(currentLine, col),
		}
	}

	if ctx := checkJSONTypeContext(lines, line, col); ctx != nil {
		return ctx
	}

	depth := 0
	inResources := false
	resourceName := ""
	inProperties := false
	propertyName := ""
	propsDepth := 0
	depthAtCursor := 0

	for i := 0; i <= line; i++ {
		trimmed := strings.TrimSpace(lines[i])

		if i == line {
			depthAtCursor = depth
		}

		if strings.Contains(trimmed, `"Resources"`) && strings.Contains(trimmed, ":") {
			inResources = true
		}
		if inResources && depth >= 2 {
			if name := extractJSONKey(trimmed); name != "" && name != "Resources" && name != "Type" && name != "Properties" &&
				name != "Ref" && !strings.HasPrefix(name, "Fn::") {
				if !inProperties || depth == propsDepth {
					resourceName = name
				}
			}
		}
		if inResources && resourceName != "" && strings.Contains(trimmed, `"Properties"`) && strings.Contains(trimmed, ":") {
			inProperties = true
			propsDepth = depth
		}
		if inProperties && depth == propsDepth+1 {
			if name := extractJSONKey(trimmed); name != "" && name != "Properties" &&
				name != "Ref" && !strings.HasPrefix(name, "Fn::") {
				propertyName = name
			}
		}

		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
	}

	if depthAtCursor <= 1 {
		return &AnalysisContext{
			Type:         ContextTopLevel,
			ExistingKeys: findTopLevelKeysJSON(lines),
			Prefix:       extractJSONKeyPrefix(currentLine, col),
		}
	}

	if inProperties && resourceName != "" {
		if depthAtCursor > propsDepth+1 && propertyName != "" {
			return &AnalysisContext{
				Type:             ContextPropertyValue,
				ResourceName:     resourceName,
				PropertyName:     propertyName,
				ResourceTypeName: findResourceTypeJSON(lines, resourceName),
				Prefix:           extractJSONKeyPrefix(currentLine, col),
			}
		}
		return &AnalysisContext{
			Type:             ContextResourceProperties,
			ResourceName:     resourceName,
			ResourceTypeName: findResourceTypeJSON(lines, resourceName),
			Prefix:           extractJSONKeyPrefix(currentLine, col),
			ExistingKeys:     findExistingPropertiesJSON(lines, line),
		}
	}

	if inResources && resourceName != "" {
		if ctx := checkJSONConditionValueContext(currentLine, col); ctx != nil {
			return ctx
		}
		return &AnalysisContext{
			Type:             ContextResourceBlock,
			ResourceName:     resourceName,
			ResourceTypeName: findResourceTypeJSON(lines, resourceName),
			Prefix:           extractJSONKeyPrefix(currentLine, col),
		}
	}

	return &AnalysisContext{Type: ContextUnknown}
}

// findJSONSection determines the enclosing top-level section (e.g., "Parameters",
// "Resources") for a given line in a JSON template.
func findJSONSection(lines []string, line int) string {
	braceDepth := 0
	for i := line; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		braceDepth += strings.Count(trimmed, "}") - strings.Count(trimmed, "{")
		if braceDepth <= -1 {
			key := extractJSONKey(trimmed)
			if key == "Parameters" || key == "Resources" || key == "Outputs" ||
				key == "Conditions" || key == "Mappings" || key == "Metadata" || key == "Locals" {
				return key
			}
		}
	}
	return ""
}

// checkJSONOutputContext detects output-related contexts in JSON:
// ContextPropertyValue when inside a "Value" field, ContextConditionValue
// when at the "Condition" value, or ContextOutputBlock when at the output
// block key level (Value, Description, Condition).
func checkJSONOutputContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	// Check if the current line has "Value" key with cursor after colon
	if strings.Contains(trimmed, `"Value"`) && strings.Contains(trimmed, ":") {
		colonIdx := strings.Index(currentLine, ":")
		if colonIdx >= 0 && col > colonIdx {
			return &AnalysisContext{
				Type:   ContextPropertyValue,
				Prefix: extractJSONKeyPrefix(currentLine, col),
			}
		}
	}

	// Check if the current line has "Condition" key with cursor after colon → condition names
	if ctx := checkJSONConditionValueContext(currentLine, col); ctx != nil {
		return ctx
	}

	// Check if we're inside a nested object under "Value"
	braceDepth := 0
	for i := line; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		braceDepth += strings.Count(lt, "}") - strings.Count(lt, "{")
		if braceDepth <= -1 {
			key := extractJSONKey(lt)
			if key == "Value" {
				return &AnalysisContext{
					Type:   ContextPropertyValue,
					Prefix: extractJSONKeyPrefix(currentLine, col),
				}
			}
			if key == "Description" || key == "Condition" {
				return nil
			}
			break
		}
	}

	// At the output block key level: depth 3 means inside Outputs > OutputName > {keys}
	depth := 0
	outputName := ""
	for i := 0; i <= line; i++ {
		lt := strings.TrimSpace(lines[i])
		if depth == 2 {
			if key := extractJSONKey(lt); key != "" && key != "Outputs" {
				outputName = key
			}
		}
		depth += strings.Count(lt, "{") - strings.Count(lt, "}")
	}
	if depth >= 3 && outputName != "" {
		return &AnalysisContext{
			Type:         ContextOutputBlock,
			ResourceName: outputName,
			Prefix:       extractJSONKeyPrefix(currentLine, col),
			ExistingKeys: findExistingOutputKeysJSON(lines, line),
		}
	}

	// On the output name line after ':' (e.g., "OutputName":| )
	// depth 2 means inside Outputs > {output names}
	if depth == 2 && outputName != "" {
		key := extractJSONKey(trimmed)
		if key != "" && !isOutputBlockKey(key) {
			colonIdx := strings.Index(currentLine, ":")
			if colonIdx >= 0 && col > colonIdx {
				return &AnalysisContext{
					Type:         ContextOutputBlock,
					ResourceName: key,
					ExistingKeys: nil,
				}
			}
		}
	}

	return nil
}

// findExistingOutputKeysJSON collects existing keys at the same brace depth level
// inside an output definition in JSON.
func findExistingOutputKeysJSON(lines []string, line int) []string {
	targetDepth := 0
	for i := 0; i <= line; i++ {
		lt := strings.TrimSpace(lines[i])
		targetDepth += strings.Count(lt, "{") - strings.Count(lt, "}")
	}

	depth := 0
	var keys []string
	for i := 0; i < len(lines); i++ {
		lt := strings.TrimSpace(lines[i])
		prevDepth := depth
		depth += strings.Count(lt, "{") - strings.Count(lt, "}")
		if prevDepth == targetDepth || depth == targetDepth {
			if key := extractJSONKey(lt); key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// checkJSONParameterTypeContext detects if the cursor is on a "Type" value
// inside a Parameters section in a JSON template.
func checkJSONParameterTypeContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	typeIdx := strings.Index(currentLine, `"Type"`)
	if typeIdx < 0 {
		return nil
	}

	rest := currentLine[typeIdx+6:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil
	}

	afterColon := rest[colonIdx+1:]
	quoteIdx := strings.Index(afterColon, `"`)
	if quoteIdx < 0 {
		return nil
	}

	valueStartCol := typeIdx + 6 + colonIdx + 1 + quoteIdx + 1
	if col < valueStartCol {
		return nil
	}

	prefix := ""
	endPos := col
	if endPos > len(currentLine) {
		endPos = len(currentLine)
	}
	if endPos > valueStartCol {
		prefix = currentLine[valueStartCol:endPos]
		prefix = strings.TrimRight(prefix, `"`)
	}

	return &AnalysisContext{
		Type:          ContextParameterTypeValue,
		Prefix:        prefix,
		ValueStartCol: valueStartCol,
	}
}

// checkJSONAssociationPropertyContext detects if the cursor is on an "AssociationProperty"
// value inside a Parameters section in a JSON template.
func checkJSONAssociationPropertyContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	apIdx := strings.Index(currentLine, `"AssociationProperty"`)
	if apIdx < 0 {
		return nil
	}
	if strings.Contains(currentLine, `"AssociationPropertyMetadata"`) {
		metaIdx := strings.Index(currentLine, `"AssociationPropertyMetadata"`)
		if metaIdx == apIdx {
			return nil
		}
	}

	rest := currentLine[apIdx+len(`"AssociationProperty"`):]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil
	}

	afterColon := rest[colonIdx+1:]
	quoteIdx := strings.Index(afterColon, `"`)
	if quoteIdx < 0 {
		return nil
	}

	valueStartCol := apIdx + len(`"AssociationProperty"`) + colonIdx + 1 + quoteIdx + 1
	if col < valueStartCol {
		return nil
	}

	prefix := ""
	endPos := col
	if endPos > len(currentLine) {
		endPos = len(currentLine)
	}
	if endPos > valueStartCol {
		prefix = currentLine[valueStartCol:endPos]
		prefix = strings.TrimRight(prefix, `"`)
	}

	return &AnalysisContext{
		Type:          ContextAssociationPropertyValue,
		Prefix:        prefix,
		ValueStartCol: valueStartCol,
	}
}

// checkJSONAssociationPropertyMetadataContext detects if the cursor is inside
// an "AssociationPropertyMetadata" object in a JSON template.
func checkJSONAssociationPropertyMetadataContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	if strings.Contains(trimmed, `"AssociationPropertyMetadata"`) && strings.Contains(trimmed, ":") {
		return nil
	}

	depth := 0
	metadataLine := -1
	for i := line; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if i < line {
			depth += strings.Count(l, "}") - strings.Count(l, "{")
		}
		if strings.Contains(l, `"AssociationPropertyMetadata"`) && strings.Contains(l, ":") {
			if depth <= 0 {
				metadataLine = i
				break
			}
		}
		if depth < 0 {
			break
		}
	}
	if metadataLine < 0 {
		return nil
	}

	assocPropValue := findJSONSiblingValue(lines, metadataLine, `"AssociationProperty"`)

	existingKeys := findJSONExistingKeysInObject(lines, line, metadataLine)

	return &AnalysisContext{
		Type:             ContextAssociationPropertyMetadataKey,
		ResourceTypeName: assocPropValue,
		Prefix:           extractJSONKeyPrefix(currentLine, col),
		ExistingKeys:     existingKeys,
	}
}

// findJSONSiblingValue finds a sibling key's value at the same object level in JSON.
func findJSONSiblingValue(lines []string, fromLine int, key string) string {
	depth := 0
	for i := fromLine - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		depth += strings.Count(l, "}") - strings.Count(l, "{")
		if depth < 0 {
			break
		}
		if depth == 0 && strings.Contains(l, key) {
			colonIdx := strings.Index(l, ":")
			if colonIdx >= 0 {
				val := strings.TrimSpace(l[colonIdx+1:])
				val = strings.Trim(val, `",`)
				return val
			}
		}
	}
	depth = 0
	for i := fromLine + 1; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if depth < 0 {
			break
		}
		if depth == 0 && strings.Contains(l, key) {
			colonIdx := strings.Index(l, ":")
			if colonIdx >= 0 {
				val := strings.TrimSpace(l[colonIdx+1:])
				val = strings.Trim(val, `",`)
				return val
			}
		}
	}
	return ""
}

// findJSONExistingKeysInObject finds existing keys within the current JSON object.
func findJSONExistingKeysInObject(lines []string, currentLine, objectStartLine int) []string {
	depth := 0
	started := false
	var keys []string
	for i := objectStartLine; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if !started && strings.Contains(l, "{") {
			started = true
		}
		if started && depth <= 0 {
			break
		}
		if i != currentLine && started && depth == 1 {
			if idx := strings.Index(l, `"`); idx >= 0 {
				endIdx := strings.Index(l[idx+1:], `"`)
				if endIdx >= 0 {
					key := l[idx+1 : idx+1+endIdx]
					keys = append(keys, key)
				}
			}
		}
	}
	return keys
}

func checkJSONTypeContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	typeIdx := strings.Index(currentLine, `"Type"`)
	if typeIdx < 0 {
		return nil
	}

	rest := currentLine[typeIdx+6:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil
	}

	afterColon := rest[colonIdx+1:]
	quoteIdx := strings.Index(afterColon, `"`)
	if quoteIdx < 0 {
		return nil
	}

	valueStartCol := typeIdx + 6 + colonIdx + 1 + quoteIdx + 1
	if col < valueStartCol {
		return nil
	}

	prefix := ""
	endPos := col
	if endPos > len(currentLine) {
		endPos = len(currentLine)
	}
	if endPos > valueStartCol {
		prefix = currentLine[valueStartCol:endPos]
		prefix = strings.TrimRight(prefix, `"`)
	}

	resourceName := findResourceNameJSON(lines, line)

	return &AnalysisContext{
		Type:          ContextResourceType,
		ResourceName:  resourceName,
		Prefix:        prefix,
		ValueStartCol: valueStartCol,
	}
}

func findResourceNameJSON(lines []string, line int) string {
	indent := countIndent(lines[line])
	for i := line - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed == "{" || trimmed == "}" || trimmed == "}," {
			continue
		}
		lineIndent := countIndent(lines[i])
		if lineIndent < indent {
			key := extractJSONKey(trimmed)
			if key != "" && key != "Resources" && key != "Properties" && key != "Type" {
				return key
			}
			indent = lineIndent
		}
	}
	return ""
}

func findResourceTypeJSON(lines []string, resourceName string) string {
	foundResource := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"`+resourceName+`"`) {
			foundResource = true
			continue
		}
		if foundResource && strings.Contains(trimmed, `"Type"`) {
			// Extract value after colon
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `",`)
				return val
			}
		}
	}
	return ""
}

// FindJSONKeyEditRange finds the range of a JSON key being typed at the cursor position.
// It locates the surrounding quotes and returns the start (inclusive) and end (exclusive) columns.
// Returns found=false if no valid quote range is detected.
func FindJSONKeyEditRange(line string, col int) (startCol, endCol int, found bool) {
	if col > len(line) {
		col = len(line)
	}

	startCol = -1
	for i := col - 1; i >= 0; i-- {
		if line[i] == '"' {
			startCol = i
			break
		}
		if line[i] == ':' || line[i] == '{' || line[i] == '}' || line[i] == ',' || line[i] == '[' || line[i] == ']' {
			break
		}
	}
	if startCol < 0 {
		return 0, 0, false
	}

	endCol = col
	for i := col; i < len(line); i++ {
		if line[i] == '"' {
			endCol = i + 1
			break
		}
		if line[i] == ':' || line[i] == '{' || line[i] == '}' || line[i] == ',' {
			break
		}
	}

	return startCol, endCol, true
}

// FindJSONValueEnd finds the end of a JSON string value starting at valueStartCol.
// Returns the end column (exclusive), whether a closing quote was found, and whether a trailing comma exists.
func FindJSONValueEnd(line string, valueStartCol int) (endCol int, hasClosingQuote bool, hasComma bool) {
	endCol = len(line)
	for i := valueStartCol; i < len(line); i++ {
		if line[i] == '"' {
			hasClosingQuote = true
			endCol = i + 1
			for j := i + 1; j < len(line); j++ {
				if line[j] == ',' {
					hasComma = true
					endCol = j + 1
					break
				} else if line[j] != ' ' && line[j] != '\t' {
					break
				}
			}
			break
		}
	}
	return
}

// ExtractJSONTypeValue extracts the resource type name from a JSON "Type": "..." line.
func ExtractJSONTypeValue(line string) string {
	trimmed := strings.TrimSpace(line)
	idx := strings.Index(trimmed, `"Type"`)
	if idx < 0 {
		return ""
	}
	rest := trimmed[idx+6:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return ""
	}
	afterColon := strings.TrimSpace(rest[colonIdx+1:])
	if len(afterColon) < 2 || afterColon[0] != '"' {
		return ""
	}
	closeIdx := strings.Index(afterColon[1:], `"`)
	if closeIdx < 0 {
		return ""
	}
	return afterColon[1 : closeIdx+1]
}

func extractJSONKey(line string) string {
	idx := strings.Index(line, `"`)
	if idx < 0 {
		return ""
	}
	rest := line[idx+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// checkJSONRefContext detects if the cursor is in a "Ref": "value" position in JSON.
func checkJSONRefContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	refIdx := strings.Index(trimmed, `"Ref"`)
	if refIdx < 0 {
		return nil
	}

	rest := trimmed[refIdx+5:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil
	}

	afterColon := rest[colonIdx+1:]
	quoteIdx := strings.Index(afterColon, `"`)
	if quoteIdx < 0 {
		return nil
	}

	lineRefIdx := strings.Index(currentLine, `"Ref"`)
	valueStartCol := lineRefIdx + 5 + colonIdx + 1 + quoteIdx + 1
	if col < valueStartCol {
		return nil
	}

	prefix := ""
	endPos := col
	if endPos > len(currentLine) {
		endPos = len(currentLine)
	}
	if endPos > valueStartCol {
		prefix = currentLine[valueStartCol:endPos]
		prefix = strings.TrimRight(prefix, `"`)
	}

	resourceName := findEnclosingResourceNameJSON(lines, line)
	return &AnalysisContext{
		Type:         ContextRefValue,
		ResourceName: resourceName,
		Prefix:       prefix,
	}
}

// checkJSONGetAttContext detects if the cursor is in a "Fn::GetAtt": [...] position in JSON.
func checkJSONGetAttContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	if strings.Contains(trimmed, `"Fn::GetAtt"`) {
		return checkJSONGetAttInline(currentLine, lines, line, col)
	}

	// Check if we're inside a GetAtt array on a separate line: the array element lines
	// under a "Fn::GetAtt": [ ... ] that spans multiple lines.
	for i := line; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		if strings.Contains(lt, `"Fn::GetAtt"`) {
			return checkJSONGetAttMultiline(lines, i, line, col)
		}
		if strings.ContainsAny(lt, "{}") && !strings.Contains(lt, "[") {
			break
		}
	}

	return nil
}

func checkJSONGetAttInline(currentLine string, lines []string, line, col int) *AnalysisContext {
	bracketIdx := strings.Index(currentLine, "[")
	if bracketIdx < 0 {
		return nil
	}

	if col <= bracketIdx {
		return nil
	}

	afterBracket := currentLine[bracketIdx+1:]

	resourceName := findEnclosingResourceNameJSON(lines, line)

	// Find all quoted strings in the array portion
	elements, positions := extractJSONArrayElements(afterBracket, bracketIdx+1)

	// Determine which element the cursor is in
	for idx, pos := range positions {
		if col >= pos.start && col <= pos.end {
			prefix := ""
			if col > pos.start && col <= pos.end {
				prefix = currentLine[pos.start:col]
				prefix = strings.TrimRight(prefix, `"`)
			}
			if idx == 0 {
				return &AnalysisContext{
					Type:         ContextGetAttResource,
					Prefix:       prefix,
					ResourceName: resourceName,
				}
			}
			resLogicalID := ""
			if len(elements) > 0 {
				resLogicalID = elements[0]
			}
			return &AnalysisContext{
				Type:               ContextGetAttAttribute,
				GetAttResourceName: resLogicalID,
				Prefix:             prefix,
				ResourceName:       resourceName,
			}
		}
	}

	// Cursor might be between elements or after last comma — check if past the bracket
	lastQuoteEnd := bracketIdx + 1
	for _, pos := range positions {
		if pos.end > lastQuoteEnd {
			lastQuoteEnd = pos.end
		}
	}
	if col > lastQuoteEnd {
		if len(elements) == 0 {
			return &AnalysisContext{
				Type:         ContextGetAttResource,
				Prefix:       "",
				ResourceName: resourceName,
			}
		}
		if len(elements) == 1 {
			return &AnalysisContext{
				Type:               ContextGetAttAttribute,
				GetAttResourceName: elements[0],
				Prefix:             "",
				ResourceName:       resourceName,
			}
		}
	}

	return nil
}

type jsonArrayPos struct {
	start int // column of first char inside quotes
	end   int // column of closing quote (exclusive content end)
}

func extractJSONArrayElements(arrayContent string, offset int) ([]string, []jsonArrayPos) {
	var elements []string
	var positions []jsonArrayPos

	i := 0
	for i < len(arrayContent) {
		if arrayContent[i] == '"' {
			start := i + 1
			end := strings.Index(arrayContent[start:], `"`)
			if end < 0 {
				// Unclosed quote — content up to end
				elements = append(elements, arrayContent[start:])
				positions = append(positions, jsonArrayPos{start: offset + start, end: offset + len(arrayContent)})
				break
			}
			elements = append(elements, arrayContent[start:start+end])
			positions = append(positions, jsonArrayPos{start: offset + start, end: offset + start + end})
			i = start + end + 1
		} else if arrayContent[i] == ']' {
			break
		} else {
			i++
		}
	}
	return elements, positions
}

func checkJSONGetAttMultiline(lines []string, getAttLine, cursorLine, col int) *AnalysisContext {
	// Count array items between getAttLine and cursorLine
	itemIndex := 0
	var firstElement string
	for i := getAttLine; i <= cursorLine; i++ {
		lt := strings.TrimSpace(lines[i])
		if i == getAttLine {
			// Check if array starts on same line
			if bracketIdx := strings.Index(lt, "["); bracketIdx >= 0 {
				after := lt[bracketIdx+1:]
				// Check for first element on same line
				q1 := strings.Index(after, `"`)
				if q1 >= 0 {
					q2 := strings.Index(after[q1+1:], `"`)
					if q2 >= 0 {
						firstElement = after[q1+1 : q1+1+q2]
						itemIndex++
					}
				}
			}
			continue
		}
		if i == cursorLine {
			break
		}
		// Count string items on intermediate lines
		if strings.Contains(lt, `"`) {
			if firstElement == "" {
				key := extractJSONKey(lt)
				if key != "" {
					firstElement = key
				}
			}
			itemIndex++
		}
	}

	currentLine := lines[cursorLine]
	prefix := extractJSONValuePrefix(currentLine, col)

	resourceName := findEnclosingResourceNameJSON(lines, cursorLine)

	if itemIndex == 0 {
		return &AnalysisContext{
			Type:         ContextGetAttResource,
			Prefix:       prefix,
			ResourceName: resourceName,
		}
	}

	return &AnalysisContext{
		Type:               ContextGetAttAttribute,
		GetAttResourceName: firstElement,
		Prefix:             prefix,
		ResourceName:       resourceName,
	}
}

// findEnclosingResourceNameJSON finds the resource logical ID enclosing the given line in JSON.
func findEnclosingResourceNameJSON(lines []string, line int) string {
	braceDepth := 0
	for i := line; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		braceDepth += strings.Count(trimmed, "}") - strings.Count(trimmed, "{")

		if braceDepth <= -2 {
			key := extractJSONKey(trimmed)
			if key != "" && key != "Resources" && key != "Properties" && key != "Type" &&
				key != "Ref" && !strings.HasPrefix(key, "Fn::") {
				return key
			}
		}
	}
	return ""
}

// extractJSONValuePrefix extracts a value prefix from a JSON line at the given cursor column.
// For "some text" it returns the text between the opening quote and cursor.
func extractJSONValuePrefix(line string, col int) string {
	if col > len(line) {
		col = len(line)
	}
	// Walk backwards from cursor to find opening quote
	for i := col - 1; i >= 0; i-- {
		if line[i] == '"' {
			if col > i+1 {
				return strings.TrimRight(line[i+1:col], `"`)
			}
			return ""
		}
		if line[i] == '[' || line[i] == ',' || line[i] == '{' || line[i] == ':' {
			break
		}
	}
	return ""
}

// extractJSONKeyPrefix extracts the key prefix being typed in a JSON line.
// For `    "Re` it returns "Re".
func extractJSONKeyPrefix(line string, col int) string {
	if col > len(line) {
		col = len(line)
	}
	for i := col - 1; i >= 0; i-- {
		if line[i] == '"' {
			if col > i+1 {
				return strings.TrimRight(line[i+1:col], `"`)
			}
			return ""
		}
		if line[i] == '{' || line[i] == ',' || line[i] == '}' || line[i] == ':' {
			break
		}
	}
	start := col
	for i := col - 1; i >= 0; i-- {
		c := line[i]
		if c == ' ' || c == '\t' || c == '{' || c == ',' || c == '}' || c == ':' || c == '"' {
			break
		}
		start = i
	}
	if start < col {
		return line[start:col]
	}
	return ""
}

func findTopLevelKeysJSON(lines []string) []string {
	var keys []string
	depth := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		prevDepth := depth
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")

		if prevDepth == 1 {
			key := extractJSONKey(trimmed)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

func findExistingPropertiesJSON(lines []string, currentLine int) []string {
	propLine := -1
	for i := currentLine; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.Contains(trimmed, `"Properties"`) && strings.Contains(trimmed, ":") {
			propLine = i
			break
		}
	}
	if propLine < 0 {
		return nil
	}

	propIndent := countIndent(lines[propLine])
	targetIndent := propIndent + DetectIndentStep(lines, propLine+1)

	var keys []string
	depth := 0
	for i := propLine; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if i > propLine && depth <= 0 {
			break
		}
		ind := countIndent(lines[i])
		if i > propLine && ind == targetIndent {
			key := extractJSONKey(trimmed)
			if key != "" && key != "Properties" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

func findExistingParameterAttrsJSON(lines []string, currentLine int) []string {
	paramLine := -1
	indent := countIndent(lines[currentLine])
	for i := currentLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed == "{" {
			continue
		}
		ind := countIndent(lines[i])
		if ind < indent {
			paramLine = i
			break
		}
	}
	if paramLine < 0 {
		return nil
	}

	targetIndent := indent
	var keys []string
	depth := 0
	for i := paramLine; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if i > paramLine && depth <= 0 {
			break
		}
		ind := countIndent(lines[i])
		if i > paramLine && ind == targetIndent {
			key := extractJSONKey(trimmed)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

func findParameterNameJSON(lines []string, line int) string {
	indent := countIndent(lines[line])
	for i := line - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed == "{" || trimmed == "}" || trimmed == "}," {
			continue
		}
		lineIndent := countIndent(lines[i])
		if lineIndent < indent {
			key := extractJSONKey(trimmed)
			if key != "" && key != "Parameters" {
				return key
			}
			indent = lineIndent
		}
	}
	return ""
}

// checkJSONLocalsContext detects locals-related contexts in JSON templates.
func checkJSONLocalsContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]

	if ctx := checkJSONLocalsTypeContext(lines, line, col); ctx != nil {
		return ctx
	}

	// Check if inside a Properties sub-block of a DATASOURCE local
	if ctx := checkJSONLocalsPropertiesContext(lines, line, col); ctx != nil {
		return ctx
	}

	// Check if on a "Value" line with cursor after colon → intrinsic functions
	if ctx := checkJSONLocalsValueContext(lines, line, col); ctx != nil {
		return ctx
	}

	depth := 0
	for i := 0; i <= line; i++ {
		trimmed := strings.TrimSpace(lines[i])
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
	}
	if depth >= 3 {
		localName := findLocalNameJSON(lines, line)
		return &AnalysisContext{
			Type:         ContextLocalsBlock,
			ResourceName: localName,
			Prefix:       extractJSONKeyPrefix(currentLine, col),
			ExistingKeys: findExistingLocalsAttrsJSON(lines, line),
		}
	}

	return nil
}

// checkJSONLocalsValueContext detects if the cursor is inside a "Value" field
// of a local variable in JSON, and returns ContextPropertyValue for intrinsic
// function completions.
func checkJSONLocalsValueContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	// On the same line as "Value": with cursor after colon
	if strings.Contains(trimmed, `"Value"`) && strings.Contains(trimmed, ":") {
		colonIdx := strings.Index(currentLine, ":")
		if colonIdx >= 0 && col > colonIdx {
			return &AnalysisContext{
				Type:   ContextPropertyValue,
				Prefix: extractJSONKeyPrefix(currentLine, col),
			}
		}
	}

	// Inside a nested object under "Value"
	braceDepth := 0
	for i := line; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		braceDepth += strings.Count(lt, "}") - strings.Count(lt, "{")
		if braceDepth <= -1 {
			key := extractJSONKey(lt)
			if key == "Value" {
				return &AnalysisContext{
					Type:   ContextPropertyValue,
					Prefix: extractJSONKeyPrefix(currentLine, col),
				}
			}
			break
		}
	}

	return nil
}

// checkJSONLocalsPropertiesContext checks if the cursor is inside a Properties
// sub-block of a local variable in JSON.
func checkJSONLocalsPropertiesContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]

	// Find the enclosing key by walking backwards and tracking brace depth.
	// The first key found at depth -1 must be "Properties".
	braceDepth := 0
	propertiesLine := -1
	for i := line; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		braceDepth += strings.Count(lt, "}") - strings.Count(lt, "{")
		if braceDepth <= -1 {
			key := extractJSONKey(lt)
			if key == "Properties" {
				propertiesLine = i
			}
			break
		}
	}
	if propertiesLine < 0 {
		return nil
	}

	// Find the local variable name (parent of Properties) by continuing upward.
	localName := ""
	depth := 0
	for i := propertiesLine - 1; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		depth += strings.Count(lt, "}") - strings.Count(lt, "{")
		if depth <= -1 {
			key := extractJSONKey(lt)
			if key != "" && key != "Locals" && key != "Properties" {
				localName = key
			}
			break
		}
	}
	if localName == "" {
		return nil
	}

	localType := findLocalTypeJSON(lines, localName)
	if localType == "" {
		return nil
	}

	return &AnalysisContext{
		Type:             ContextResourceProperties,
		ResourceName:     localName,
		ResourceTypeName: localType,
		Prefix:           extractJSONKeyPrefix(currentLine, col),
		ExistingKeys:     findExistingLocalPropsJSON(lines, line, propertiesLine),
	}
}

// findLocalTypeJSON finds the Type value of a local variable in JSON.
func findLocalTypeJSON(lines []string, localName string) string {
	needle := `"` + localName + `"`
	foundLocal := false
	braceDepth := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !foundLocal {
			if strings.Contains(trimmed, needle) {
				foundLocal = true
				braceDepth = 0
			}
			continue
		}
		braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if braceDepth < 0 {
			break
		}
		if strings.Contains(trimmed, `"Type"`) && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `",`)
				return val
			}
		}
	}
	return ""
}

// findExistingLocalPropsJSON collects existing property keys inside the
// Properties object of a local variable in JSON.
func findExistingLocalPropsJSON(lines []string, currentLine, propertiesLine int) []string {
	propIndent := countIndent(lines[propertiesLine])
	targetIndent := propIndent + DetectIndentStep(lines, propertiesLine+1)

	var keys []string
	depth := 0
	for i := propertiesLine; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if i > propertiesLine && depth <= 0 {
			break
		}
		ind := countIndent(lines[i])
		if i > propertiesLine && ind == targetIndent {
			key := extractJSONKey(trimmed)
			if key != "" && key != "Properties" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// checkJSONLocalsTypeContext detects if the cursor is on a "Type" value
// inside a Locals section in a JSON template.
func checkJSONLocalsTypeContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	typeIdx := strings.Index(currentLine, `"Type"`)
	if typeIdx < 0 {
		return nil
	}

	rest := currentLine[typeIdx+6:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil
	}

	afterColon := rest[colonIdx+1:]
	quoteIdx := strings.Index(afterColon, `"`)
	if quoteIdx < 0 {
		return nil
	}

	valueStartCol := typeIdx + 6 + colonIdx + 1 + quoteIdx + 1
	if col < valueStartCol {
		return nil
	}

	prefix := ""
	endPos := col
	if endPos > len(currentLine) {
		endPos = len(currentLine)
	}
	if endPos > valueStartCol {
		prefix = currentLine[valueStartCol:endPos]
		prefix = strings.TrimRight(prefix, `"`)
	}

	return &AnalysisContext{
		Type:          ContextLocalsTypeValue,
		Prefix:        prefix,
		ValueStartCol: valueStartCol,
	}
}

func findLocalNameJSON(lines []string, line int) string {
	indent := countIndent(lines[line])
	for i := line - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed == "{" || trimmed == "}" || trimmed == "}," {
			continue
		}
		ind := countIndent(lines[i])
		if ind < indent {
			key := extractJSONKey(trimmed)
			if key != "" && key != "Locals" {
				return key
			}
			indent = ind
		}
	}
	return ""
}

func findExistingLocalsAttrsJSON(lines []string, currentLine int) []string {
	paramLine := -1
	indent := countIndent(lines[currentLine])
	for i := currentLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed == "{" {
			continue
		}
		ind := countIndent(lines[i])
		if ind < indent {
			paramLine = i
			break
		}
	}
	if paramLine < 0 {
		return nil
	}

	targetIndent := indent
	var keys []string
	depth := 0
	for i := paramLine; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if i > paramLine && depth <= 0 {
			break
		}
		ind := countIndent(lines[i])
		if i > paramLine && ind == targetIndent {
			key := extractJSONKey(trimmed)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// checkJSONConditionValueContext checks if the cursor is at a "Condition": value
// in JSON. Returns ContextConditionValue if so.
func checkJSONConditionValueContext(currentLine string, col int) *AnalysisContext {
	trimmed := strings.TrimSpace(currentLine)
	if !strings.Contains(trimmed, `"Condition"`) || !strings.Contains(trimmed, ":") {
		return nil
	}
	key := extractJSONKey(trimmed)
	if key != "Condition" {
		return nil
	}
	colonIdx := -1
	inQuote := false
	for i := 0; i < len(currentLine); i++ {
		if currentLine[i] == '"' {
			inQuote = !inQuote
		}
		if currentLine[i] == ':' && !inQuote {
			colonIdx = i
			break
		}
	}
	if colonIdx < 0 || col <= colonIdx {
		return nil
	}
	prefix := extractJSONValuePrefix(currentLine, col)
	return &AnalysisContext{
		Type:   ContextConditionValue,
		Prefix: prefix,
	}
}

// checkJSONConditionFnContext detects Fn::If/Fn::And/Fn::Or/Fn::Not contexts in JSON.
// Returns ContextFnIfConditionName when cursor is at a condition-name argument position.
func checkJSONConditionFnContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	for _, fn := range conditionFns {
		jsonKey := `"` + fn.longForm + `"`

		// Check if the function key is on the current line
		if strings.Contains(trimmed, jsonKey) {
			colonIdx := findJSONValueColon(currentLine, fn.longForm)
			if colonIdx >= 0 && col > colonIdx {
				return parseJSONConditionFnArgs(currentLine, colonIdx+1, col, fn.allArgs)
			}
		}
	}

	// Check if we're inside an array that belongs to a condition function key above
	bracketDepth := 0
	for i := line; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		if i < line {
			bracketDepth += strings.Count(lt, "]") - strings.Count(lt, "[")
		}
		if bracketDepth <= -1 {
			for _, fn := range conditionFns {
				jsonKey := `"` + fn.longForm + `"`
				if strings.Contains(lt, jsonKey) {
					precedingItems := countJSONArrayItemsBefore(lines, i, line)
					if fn.allArgs || precedingItems == 0 {
						prefix := extractJSONValuePrefix(currentLine, col)
						return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: prefix}
					}
					return nil
				}
			}
			break
		}
	}

	return nil
}

// findJSONValueColon finds the colon that separates a JSON key from its value,
// skipping colons inside quoted strings.
func findJSONValueColon(line, fnName string) int {
	inQuote := false
	for ci := 0; ci < len(line); ci++ {
		if line[ci] == '"' {
			inQuote = !inQuote
		}
		if line[ci] == ':' && !inQuote {
			if ci > 0 && strings.Contains(line[:ci], fnName) {
				return ci
			}
		}
	}
	return -1
}

// countJSONArrayItemsBefore counts complete array items between startLine
// and endLine (exclusive, the current cursor line).
func countJSONArrayItemsBefore(lines []string, startLine, endLine int) int {
	count := 0
	braceDepth := 0
	for i := startLine + 1; i < endLine; i++ {
		lt := strings.TrimSpace(lines[i])
		if lt == "" || lt == "[" {
			continue
		}
		prevDepth := braceDepth
		braceDepth += strings.Count(lt, "{") - strings.Count(lt, "}")
		if prevDepth == 0 && braceDepth == 0 {
			count++
		}
	}
	return count
}

// parseJSONConditionFnArgs parses inline condition function array args on a single line.
func parseJSONConditionFnArgs(line string, afterColon, col int, allArgs bool) *AnalysisContext {
	if col > len(line) {
		col = len(line)
	}
	afterPart := strings.TrimSpace(line[afterColon:col])
	afterPart = strings.TrimLeft(afterPart, "[ ")

	if afterPart == "" {
		return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: ""}
	}

	parts := splitJSONArrayArgs(afterPart)
	if allArgs {
		prefix := strings.Trim(strings.TrimSpace(parts[len(parts)-1]), `"`)
		return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: prefix}
	}
	if len(parts) <= 1 {
		prefix := strings.Trim(strings.TrimSpace(parts[0]), `"`)
		return &AnalysisContext{
			Type:   ContextFnIfConditionName,
			Prefix: prefix,
		}
	}
	return nil
}

// checkJSONFindInMapContext detects Fn::FindInMap contexts in JSON.
func checkJSONFindInMapContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	// Check if "Fn::FindInMap" key is on the current line
	if strings.Contains(trimmed, `"Fn::FindInMap"`) {
		colonIdx := -1
		inQuote := false
		for ci := 0; ci < len(currentLine); ci++ {
			if currentLine[ci] == '"' {
				inQuote = !inQuote
			}
			if currentLine[ci] == ':' && !inQuote {
				if ci > 0 && strings.Contains(currentLine[:ci], "Fn::FindInMap") {
					colonIdx = ci
					break
				}
			}
		}
		if colonIdx >= 0 && col > colonIdx {
			return parseJSONFindInMapArgs(currentLine, colonIdx+1, col)
		}
	}

	// Check if we're inside an array that belongs to a "Fn::FindInMap" key above
	bracketDepth := 0
	for i := line; i >= 0; i-- {
		lt := strings.TrimSpace(lines[i])
		if i < line {
			bracketDepth += strings.Count(lt, "]") - strings.Count(lt, "[")
		}
		if bracketDepth <= -1 {
			if strings.Contains(lt, `"Fn::FindInMap"`) {
				items := collectJSONArrayItems(lines, i, line)
				prefix := extractJSONValuePrefix(currentLine, col)
				switch len(items) {
				case 0:
					return &AnalysisContext{Type: ContextFindInMapMapName, Prefix: prefix}
				case 1:
					return &AnalysisContext{
						Type:             ContextFindInMapFirstKey,
						FindInMapMapName: items[0],
						Prefix:           prefix,
					}
				default:
					return &AnalysisContext{
						Type:              ContextFindInMapSecondKey,
						FindInMapMapName:  items[0],
						FindInMapFirstKey: items[1],
						Prefix:            prefix,
					}
				}
			}
			break
		}
	}

	return nil
}

// parseJSONFindInMapArgs parses the array arguments for Fn::FindInMap on a single line.
func parseJSONFindInMapArgs(line string, afterColon, col int) *AnalysisContext {
	if col > len(line) {
		col = len(line)
	}
	afterPart := strings.TrimSpace(line[afterColon:col])
	afterPart = strings.TrimLeft(afterPart, "[ ")

	if afterPart == "" {
		return &AnalysisContext{Type: ContextFindInMapMapName, Prefix: ""}
	}

	parts := splitJSONArrayArgs(afterPart)
	for i := range parts {
		parts[i] = strings.Trim(strings.TrimSpace(parts[i]), `"`)
	}

	switch len(parts) {
	case 1:
		return &AnalysisContext{
			Type:   ContextFindInMapMapName,
			Prefix: parts[0],
		}
	case 2:
		return &AnalysisContext{
			Type:             ContextFindInMapFirstKey,
			FindInMapMapName: parts[0],
			Prefix:           parts[1],
		}
	default:
		return &AnalysisContext{
			Type:              ContextFindInMapSecondKey,
			FindInMapMapName:  parts[0],
			FindInMapFirstKey: parts[1],
			Prefix:            parts[len(parts)-1],
		}
	}
}

// splitJSONArrayArgs splits comma-separated JSON array arguments, handling quoted strings.
func splitJSONArrayArgs(s string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' && (i == 0 || s[i-1] != '\\') {
			inQuote = !inQuote
			current.WriteByte(ch)
		} else if ch == ',' && !inQuote {
			parts = append(parts, current.String())
			current.Reset()
		} else {
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// collectJSONArrayItems collects string items in a JSON array between startLine and endLine.
func collectJSONArrayItems(lines []string, startLine, endLine int) []string {
	var items []string
	braceDepth := 0
	for i := startLine; i < endLine; i++ {
		lt := strings.TrimSpace(lines[i])
		if strings.Contains(lt, "Fn::FindInMap") || lt == "" || lt == "[" || lt == "]" || lt == "," {
			continue
		}

		prevDepth := braceDepth
		braceDepth += strings.Count(lt, "{") - strings.Count(lt, "}")

		if prevDepth == 0 {
			val := extractJSONStringValue(lt)
			if val != "" {
				items = append(items, val)
			} else {
				items = append(items, "")
			}
		}
	}
	return items
}

// extractJSONStringValue extracts a quoted string value from a JSON line.
func extractJSONStringValue(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimRight(line, ",]")
	line = strings.TrimSpace(line)
	if len(line) >= 2 && line[0] == '"' && line[len(line)-1] == '"' {
		return line[1 : len(line)-1]
	}
	return ""
}
