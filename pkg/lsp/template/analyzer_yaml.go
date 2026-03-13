package template

import (
	"strings"
)

func analyzeYAMLPosition(content string, line, col int) *AnalysisContext {
	lines := strings.Split(content, "\n")
	if line < 0 || line >= len(lines) {
		return &AnalysisContext{Type: ContextUnknown}
	}

	currentLine := lines[line]
	indent := countIndent(currentLine)

	// Check for intrinsic function contexts first (these can appear anywhere in the template)
	if ctx := checkConditionFnContext(lines, line, col); ctx != nil {
		return ctx
	}
	if ctx := checkFindInMapContext(lines, line, col); ctx != nil {
		return ctx
	}
	if ctx := checkRefContext(lines, line, col); ctx != nil {
		return ctx
	}
	if ctx := checkGetAttContext(lines, line, col); ctx != nil {
		return ctx
	}

	// Top-level: no indentation
	if indent == 0 {
		ctx := &AnalysisContext{Type: ContextTopLevel}
		ctx.ExistingKeys = findTopLevelKeys(lines)
		ctx.Prefix = extractPrefix(currentLine, col)
		return ctx
	}

	// Check if the current line itself is a resource section key
	currentTrimmed := strings.TrimSpace(currentLine)
	currentKey := strings.SplitN(currentTrimmed, ":", 2)[0]
	currentKey = strings.TrimSpace(currentKey)

	// Find the parent context by looking up for less-indented lines
	resourceName, resourceSection := findResourceContext(lines, line, indent)

	// If cursor is on a section key line (like "Type:"), use that as the section
	if resourceSection == "" && isResourceSection(currentKey) {
		resourceSection = currentKey
	}

	if resourceName == "" {
		if indent > 0 {
			if paramCtx := analyzeParameterContext(lines, line, col, currentLine, indent); paramCtx != nil {
				return paramCtx
			}
			if outputCtx := analyzeOutputContext(lines, line, col, currentLine, indent); outputCtx != nil {
				return outputCtx
			}
		if localsCtx := analyzeLocalsContext(lines, line, col, currentLine, indent); localsCtx != nil {
			return localsCtx
		}
		if mappingsCtx := analyzeMappingsContext(lines, line, col, currentLine, indent); mappingsCtx != nil {
			return mappingsCtx
		}
		if conditionsCtx := analyzeConditionsContext(lines, line, col, currentLine, indent); conditionsCtx != nil {
			return conditionsCtx
		}
		return &AnalysisContext{Type: ContextUnknown}
		}
		return &AnalysisContext{Type: ContextTopLevel, ExistingKeys: findTopLevelKeys(lines)}
	}

	switch resourceSection {
	case "Type":
		ctx := &AnalysisContext{
			Type:          ContextResourceType,
			ResourceName:  resourceName,
			Prefix:        extractValuePrefix(currentLine, col),
			ValueStartCol: findValueStartCol(currentLine),
		}
		return ctx
	case "Properties":
		propIndent := findSectionIndent(lines, line, "Properties")
		if indent > propIndent && propIndent > 0 {
			propName := findPropertyName(lines, line, propIndent)
			if propName != "" {
				ctx := &AnalysisContext{
					Type:         ContextPropertyValue,
					ResourceName: resourceName,
					PropertyName: propName,
				}
				ctx.ResourceTypeName = findResourceType(lines, resourceName)
				ctx.Prefix = extractPropertyValuePrefix(currentLine, col, propName)
				return ctx
			}
		}
		// At property key level
		ctx := &AnalysisContext{
			Type:         ContextResourceProperties,
			ResourceName: resourceName,
			Prefix:       extractPrefix(currentLine, col),
		}
		ctx.ResourceTypeName = findResourceType(lines, resourceName)
		ctx.ExistingKeys = findExistingProperties(lines, line)
		return ctx
	case "Condition":
		if cvCtx := analyzeConditionValueContext(lines, line, col, currentLine); cvCtx != nil {
			return cvCtx
		}
		fallthrough
	default:
		// Inside resource block but not in a specific section
		ctx := &AnalysisContext{
			Type:         ContextResourceBlock,
			ResourceName: resourceName,
			Prefix:       extractPrefix(currentLine, col),
		}
		ctx.ResourceTypeName = findResourceType(lines, resourceName)
		return ctx
	}
}

// checkRefContext detects if the cursor is in a Ref: value position.
func checkRefContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)

	// Check for "Ref: <cursor>" pattern
	if strings.HasPrefix(trimmed, "Ref:") {
		colonIdx := strings.Index(currentLine, "Ref:") + 4
		if col >= colonIdx {
			prefix := ""
			if col > colonIdx && col <= len(currentLine) {
				prefix = strings.TrimSpace(currentLine[colonIdx:col])
			}
			resourceName := findEnclosingResourceName(lines, line)
			return &AnalysisContext{
				Type:         ContextRefValue,
				ResourceName: resourceName,
				Prefix:       prefix,
			}
		}
	}

	// Check for "!Ref <cursor>" inline pattern
	refIdx := strings.Index(currentLine, "!Ref ")
	if refIdx >= 0 && col >= refIdx+5 {
		prefix := ""
		if col <= len(currentLine) {
			prefix = strings.TrimSpace(currentLine[refIdx+5 : col])
		}
		resourceName := findEnclosingResourceName(lines, line)
		return &AnalysisContext{
			Type:         ContextRefValue,
			ResourceName: resourceName,
			Prefix:       prefix,
		}
	}
	// Handle "!Ref" at end of line (no trailing space) with cursor right after it
	if strings.HasSuffix(trimmed, "!Ref") {
		refPos := strings.Index(currentLine, "!Ref")
		if col >= refPos+4 {
			resourceName := findEnclosingResourceName(lines, line)
			return &AnalysisContext{
				Type:         ContextRefValue,
				ResourceName: resourceName,
				Prefix:       "",
			}
		}
	}

	return nil
}

// checkGetAttContext detects if the cursor is in a Fn::GetAtt parameter position.
func checkGetAttContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)
	indent := countIndent(currentLine)

	// Check for "!GetAtt " inline pattern: !GetAtt ResourceID.Attribute
	getAttIdx := strings.Index(currentLine, "!GetAtt ")
	if getAttIdx >= 0 && col >= getAttIdx+8 {
		valPart := ""
		if col <= len(currentLine) {
			valPart = strings.TrimSpace(currentLine[getAttIdx+8 : col])
		}
		dotIdx := strings.Index(valPart, ".")
		if dotIdx >= 0 {
			resName := valPart[:dotIdx]
			attrPrefix := valPart[dotIdx+1:]
			return &AnalysisContext{
				Type:               ContextGetAttAttribute,
				GetAttResourceName: resName,
				Prefix:             attrPrefix,
				ResourceName:       findEnclosingResourceName(lines, line),
			}
		}
		return &AnalysisContext{
			Type:         ContextGetAttResource,
			Prefix:       valPart,
			ResourceName: findEnclosingResourceName(lines, line),
		}
	}
	// Handle "!GetAtt" at end of line (no trailing space)
	if strings.HasSuffix(trimmed, "!GetAtt") {
		gaPos := strings.Index(currentLine, "!GetAtt")
		if col >= gaPos+7 {
			return &AnalysisContext{
				Type:         ContextGetAttResource,
				Prefix:       "",
				ResourceName: findEnclosingResourceName(lines, line),
			}
		}
	}

	// Check for long form: list item under "Fn::GetAtt:"
	if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
		for i := line - 1; i >= 0; i-- {
			l := strings.TrimSpace(lines[i])
			li := countIndent(lines[i])
			if li < indent {
				if strings.HasPrefix(l, "Fn::GetAtt:") || l == "Fn::GetAtt" {
					itemIndex := 0
					for j := i + 1; j < line; j++ {
						jl := strings.TrimSpace(lines[j])
						if strings.HasPrefix(jl, "- ") {
							itemIndex++
						}
					}
					prefix := ""
					dashIdx := strings.Index(currentLine, "-")
					if dashIdx >= 0 && col > dashIdx+2 && col <= len(currentLine) {
						prefix = strings.TrimSpace(currentLine[dashIdx+2 : col])
					}
					if itemIndex == 0 {
						return &AnalysisContext{
							Type:         ContextGetAttResource,
							Prefix:       prefix,
							ResourceName: findEnclosingResourceName(lines, line),
						}
					}
					// Second item: find resource from first item
					resourceLogicalID := ""
					for j := i + 1; j < line; j++ {
						jl := strings.TrimSpace(lines[j])
						if strings.HasPrefix(jl, "- ") {
							resourceLogicalID = strings.TrimSpace(strings.TrimPrefix(jl, "- "))
							break
						}
					}
					return &AnalysisContext{
						Type:               ContextGetAttAttribute,
						GetAttResourceName: resourceLogicalID,
						Prefix:             prefix,
						ResourceName:       findEnclosingResourceName(lines, line),
					}
				}
				break
			}
		}
	}

	// Check for "Fn::GetAtt:" on current line (cursor is on the value side)
	if strings.HasPrefix(trimmed, "Fn::GetAtt:") {
		colonIdx := strings.Index(currentLine, "Fn::GetAtt:") + 11
		if col >= colonIdx {
			valPart := ""
			if col <= len(currentLine) {
				valPart = strings.TrimSpace(currentLine[colonIdx:col])
			}
			return &AnalysisContext{
				Type:         ContextGetAttResource,
				Prefix:       valPart,
				ResourceName: findEnclosingResourceName(lines, line),
			}
		}
	}

	return nil
}

// findEnclosingResourceName finds the resource logical ID that encloses the given line
// by walking backwards to find the shallowest key under the Resources section.
func findEnclosingResourceName(lines []string, currentLine int) string {
	bestIndent := -1
	bestName := ""

	for i := currentLine - 1; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		ind := countIndent(line)

		if ind == 0 {
			if strings.HasPrefix(trimmed, "Resources:") || trimmed == "Resources" {
				return bestName
			}
			return ""
		}

		if bestIndent < 0 || ind < bestIndent {
			bestIndent = ind
			key := strings.SplitN(trimmed, ":", 2)[0]
			bestName = strings.TrimSpace(key)
		}
	}
	return ""
}

// --- YAML helper functions ---

func extractPrefix(line string, col int) string {
	trimmed := strings.TrimSpace(line)
	if col <= 0 {
		return ""
	}
	if col > len(line) {
		col = len(line)
	}
	prefix := strings.TrimSpace(line[:col])
	// Remove trailing colon if present
	prefix = strings.TrimSuffix(prefix, ":")
	if prefix == trimmed {
		return prefix
	}
	return prefix
}

// extractPropertyValuePrefix extracts the value prefix at the cursor position
// for a property value context. If the property key is on the same line (inline),
// the prefix is the text after the colon. Otherwise, it's the trimmed line content.
func extractPropertyValuePrefix(line string, col int, propName string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, propName+":") {
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			return ""
		}
		valueStart := colonIdx + 1
		for valueStart < len(line) && (line[valueStart] == ' ' || line[valueStart] == '\t') {
			valueStart++
		}
		endCol := col
		if endCol > len(line) {
			endCol = len(line)
		}
		if endCol > valueStart {
			return strings.TrimSpace(line[valueStart:endCol])
		}
		return ""
	}
	endCol := col
	if endCol > len(line) {
		endCol = len(line)
	}
	return strings.TrimSpace(line[:endCol])
}

func extractValuePrefix(line string, col int) string {
	// For "Type: ALIYUN::EC|", extract "ALIYUN::EC" (value before cursor only)
	idx := strings.Index(line, ":")
	if idx < 0 {
		return extractPrefix(line, col)
	}
	valueStart := idx + 1
	if col <= valueStart {
		return ""
	} 
	if col > len(line) {
		col = len(line)
	}
	valPart := strings.TrimLeft(line[valueStart:col], " \t")
	return valPart
}

func findTopLevelKeys(lines []string) []string {
	var keys []string
	for _, line := range lines {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) >= 1 {
				key := strings.TrimSpace(parts[0])
				if key != "" && key != "---" {
					keys = append(keys, key)
				}
			}
		}
	}
	return keys
}

func findResourceContext(lines []string, currentLine, currentIndent int) (resourceName, section string) {
	// Walk backwards to find context hierarchy
	for i := currentLine; i >= 0; i-- {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		ind := countIndent(line)
		trimmed := strings.TrimSpace(line)

		// Top level key reached
		if ind == 0 {
			if strings.HasPrefix(trimmed, "Resources:") || trimmed == "Resources" {
				return resourceName, section
			}
			return "", ""
		}

		if ind < currentIndent {
			key := strings.SplitN(trimmed, ":", 2)[0]
			key = strings.TrimSpace(key)

			if section == "" && isResourceSection(key) {
				section = key
				currentIndent = ind
				continue
			}

			if resourceName == "" {
				resourceName = key
				currentIndent = ind
				continue
			}
		}
	}

	return "", ""
}

// analyzeParameterContext checks if the cursor is inside a Parameters block
// and returns the appropriate context for parameter property or type value completion.
func analyzeParameterContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	paramName, found := findParameterContext(lines, line, indent)
	if !found {
		return nil
	}

	trimmed := strings.TrimSpace(currentLine)
	if strings.HasPrefix(trimmed, "Type:") {
		colonPos := strings.Index(currentLine, ":")
		if colonPos >= 0 && col > colonPos {
			return &AnalysisContext{
				Type:          ContextParameterTypeValue,
				Prefix:        extractValuePrefix(currentLine, col),
				ValueStartCol: findValueStartCol(currentLine),
			}
		}
	}

	if strings.HasPrefix(trimmed, "AssociationProperty:") && !strings.HasPrefix(trimmed, "AssociationPropertyMetadata:") {
		colonPos := strings.Index(currentLine, ":")
		if colonPos >= 0 && col > colonPos {
			return &AnalysisContext{
				Type:          ContextAssociationPropertyValue,
				Prefix:        extractValuePrefix(currentLine, col),
				ValueStartCol: findValueStartCol(currentLine),
			}
		}
	}

	if ctx := checkAssociationPropertyMetadataContext(lines, line, col, currentLine, indent); ctx != nil {
		return ctx
	}

	return &AnalysisContext{
		Type:         ContextParameterProperties,
		ResourceName: paramName,
		Prefix:       extractPrefix(currentLine, col),
		ExistingKeys: findExistingParameterAttrs(lines, line, indent),
	}
}

// checkAssociationPropertyMetadataContext checks if the cursor is inside an
// AssociationPropertyMetadata block and returns a context with the current
// parameter's AssociationProperty value so we can suggest relevant metadata keys.
func checkAssociationPropertyMetadataContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	trimmed := strings.TrimSpace(currentLine)

	if strings.HasPrefix(trimmed, "AssociationPropertyMetadata:") {
		return nil
	}

	metaIndent := -1
	for i := line - 1; i >= 0; i-- {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		li := countIndent(l)
		if li < indent {
			if strings.HasPrefix(lt, "AssociationPropertyMetadata:") || lt == "AssociationPropertyMetadata" {
				metaIndent = li
				break
			}
			return nil
		}
	}
	if metaIndent < 0 {
		return nil
	}

	assocPropValue := findSiblingValue(lines, line, metaIndent, "AssociationProperty")

	existingKeys := findExistingKeysAtIndent(lines, line, indent)

	return &AnalysisContext{
		Type:             ContextAssociationPropertyMetadataKey,
		ResourceTypeName: assocPropValue,
		Prefix:           extractPrefix(currentLine, col),
		ExistingKeys:     existingKeys,
	}
}

// findSiblingValue looks for a sibling key at the same indent level and returns its value.
func findSiblingValue(lines []string, fromLine, indent int, key string) string {
	for i := fromLine - 1; i >= 0; i-- {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		li := countIndent(l)
		if li < indent {
			break
		}
		if li == indent && strings.HasPrefix(lt, key+":") {
			parts := strings.SplitN(lt, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				return strings.Trim(val, "'\"")
			}
		}
	}
	for i := fromLine + 1; i < len(lines); i++ {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		li := countIndent(l)
		if li < indent {
			break
		}
		if li == indent && strings.HasPrefix(lt, key+":") {
			parts := strings.SplitN(lt, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				return strings.Trim(val, "'\"")
			}
		}
	}
	return ""
}

// findExistingKeysAtIndent finds all keys at the same indent level around the current line.
func findExistingKeysAtIndent(lines []string, currentLine, indent int) []string {
	keys := make(map[string]bool)
	for i := currentLine - 1; i >= 0; i-- {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		li := countIndent(l)
		if li < indent {
			break
		}
		if li == indent {
			k := strings.SplitN(lt, ":", 2)[0]
			keys[strings.TrimSpace(k)] = true
		}
	}
	for i := currentLine + 1; i < len(lines); i++ {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		li := countIndent(l)
		if li < indent {
			break
		}
		if li == indent {
			k := strings.SplitN(lt, ":", 2)[0]
			keys[strings.TrimSpace(k)] = true
		}
	}
	result := make([]string, 0, len(keys))
	for k := range keys {
		result = append(result, k)
	}
	return result
}

// findParameterContext walks backwards from the current line to determine if
// the cursor is inside a Parameters block. Returns the parameter name and
// whether a valid parameter context was found.
func findParameterContext(lines []string, currentLine, currentIndent int) (paramName string, found bool) {
	tempIndent := currentIndent

	for i := currentLine; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		ind := countIndent(line)

		if ind == 0 {
			if strings.HasPrefix(trimmed, "Parameters:") || trimmed == "Parameters" {
				return paramName, paramName != ""
			}
			return "", false
		}

		if ind < tempIndent && paramName == "" {
			key := strings.SplitN(trimmed, ":", 2)[0]
			paramName = strings.TrimSpace(key)
			tempIndent = ind
		}
	}
	return "", false
}

// analyzeOutputContext checks if the cursor is inside an Outputs block and
// returns the appropriate context: ContextOutputBlock for output-level keys
// (Value, Description, Condition), or ContextPropertyValue for positions
// inside Value where intrinsic functions should be suggested.
func analyzeOutputContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	if !isInsideSection(lines, line, indent, "Outputs") {
		return nil
	}

	trimmed := strings.TrimSpace(currentLine)

	// On the same line as "Value:" with cursor after the colon → intrinsic functions
	if strings.HasPrefix(trimmed, "Value:") {
		colonPos := strings.Index(currentLine, ":")
		if colonPos >= 0 && col > colonPos {
			return &AnalysisContext{
				Type:   ContextPropertyValue,
				Prefix: extractValuePrefix(currentLine, col),
			}
		}
	}

	// On the same line as "Condition:" with cursor after the colon → condition names
	if cvCtx := analyzeConditionValueContext(lines, line, col, currentLine); cvCtx != nil {
		return cvCtx
	}

	// On a nested line under "Value:" → intrinsic functions
	valueIndent := findParentKeyIndent(lines, line, indent, "Value")
	if valueIndent >= 0 && indent > valueIndent {
		return &AnalysisContext{
			Type:   ContextPropertyValue,
			Prefix: extractPropertyValuePrefix(currentLine, col, ""),
		}
	}

	// On the output name line after ':' (e.g., "OutputName:|")
	// Offer output block completions so Value can be auto-generated
	colonIdx := strings.Index(currentLine, ":")
	if colonIdx >= 0 && col > colonIdx {
		key := strings.SplitN(trimmed, ":", 2)[0]
		key = strings.TrimSpace(key)
		if key != "" && !isOutputBlockKey(key) {
			return &AnalysisContext{
				Type:         ContextOutputBlock,
				ResourceName: key,
				ExistingKeys: nil,
			}
		}
	}

	// At the output block key level (sibling of Value, Description, Condition)
	outputName, found := findOutputContext(lines, line, indent)
	if found && outputName != "" {
		return &AnalysisContext{
			Type:         ContextOutputBlock,
			ResourceName: outputName,
			Prefix:       extractPrefix(currentLine, col),
			ExistingKeys: findExistingSiblingKeys(lines, line, indent),
		}
	}

	return nil
}

// findOutputContext walks backwards to determine if the cursor is inside an
// Outputs block. Returns the output logical name.
func findOutputContext(lines []string, currentLine, currentIndent int) (outputName string, found bool) {
	tempIndent := currentIndent
	for i := currentLine; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		ind := countIndent(line)
		if ind == 0 {
			if strings.HasPrefix(trimmed, "Outputs:") || trimmed == "Outputs" {
				return outputName, outputName != ""
			}
			return "", false
		}
		if ind < tempIndent && outputName == "" {
			key := strings.SplitN(trimmed, ":", 2)[0]
			outputName = strings.TrimSpace(key)
			tempIndent = ind
		}
	}
	return "", false
}

// findExistingSiblingKeys collects existing keys at the same indentation level.
func findExistingSiblingKeys(lines []string, currentLine, currentIndent int) []string {
	parentLine := -1
	for i := currentLine - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		ind := countIndent(lines[i])
		if ind < currentIndent {
			parentLine = i
			break
		}
	}
	if parentLine < 0 {
		return nil
	}

	var keys []string
	for i := parentLine + 1; i < len(lines); i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		ind := countIndent(l)
		if ind < currentIndent {
			break
		}
		if ind == currentIndent {
			key := strings.SplitN(trimmed, ":", 2)[0]
			key = strings.TrimSpace(key)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// isInsideSection checks if the cursor position is inside a given top-level section.
func isInsideSection(lines []string, line, indent int, sectionName string) bool {
	for i := line; i >= 0; i-- {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		ind := countIndent(l)
		if ind == 0 {
			return strings.HasPrefix(trimmed, sectionName+":") || trimmed == sectionName
		}
	}
	return false
}

// findParentKeyIndent finds the indent of a parent key by walking backwards.
func findParentKeyIndent(lines []string, line, currentIndent int, key string) int {
	for i := line - 1; i >= 0; i-- {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		ind := countIndent(l)
		if ind < currentIndent {
			k := strings.SplitN(trimmed, ":", 2)[0]
			if strings.TrimSpace(k) == key {
				return ind
			}
			return -1
		}
	}
	return -1
}

// findExistingParameterAttrs collects the existing attribute keys under a
// parameter definition (sibling keys at the same indentation level).
func findExistingParameterAttrs(lines []string, currentLine, currentIndent int) []string {
	parentLine := -1
	for i := currentLine - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		ind := countIndent(lines[i])
		if ind < currentIndent {
			parentLine = i
			break
		}
	}

	if parentLine < 0 {
		return nil
	}

	parentIndent := countIndent(lines[parentLine])

	var keys []string
	for i := parentLine + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		ind := countIndent(lines[i])
		if ind <= parentIndent {
			break
		}
		if ind == currentIndent {
			trimmed := strings.TrimSpace(lines[i])
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) >= 1 {
				key := strings.TrimSpace(parts[0])
				if key != "" {
					keys = append(keys, key)
				}
			}
		}
	}
	return keys
}

func findSectionIndent(lines []string, currentLine int, sectionName string) int {
	for i := currentLine; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, sectionName+":") {
			return countIndent(lines[i])
		}
	}
	return 0
}

func findPropertyName(lines []string, currentLine, propIndent int) string {
	for i := currentLine; i >= 0; i-- {
		ind := countIndent(lines[i])
		if ind == propIndent+2 {
			trimmed := strings.TrimSpace(lines[i])
			if !strings.Contains(trimmed, ":") {
				if i == currentLine {
					return ""
				}
				continue
			}
			parts := strings.SplitN(trimmed, ":", 2)
			return strings.TrimSpace(parts[0])
		}
		if ind <= propIndent {
			break
		}
	}
	return ""
}

func findResourceType(lines []string, resourceName string) string {
	foundResource := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, resourceName+":") {
			foundResource = true
			continue
		}
		if foundResource {
			ind := countIndent(line)
			if ind == 0 {
				break
			}
			if strings.HasPrefix(trimmed, "Type:") {
				return strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
			}
		}
	}
	return ""
}

func findExistingProperties(lines []string, currentLine int) []string {
	propStart := -1
	propIndent := 0
	for i := currentLine; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "Properties:") {
			propStart = i
			propIndent = countIndent(lines[i])
			break
		}
	}

	if propStart < 0 {
		return nil
	}

	var keys []string
	expectedIndent := propIndent + 2
	for i := propStart + 1; i < len(lines); i++ {
		ind := countIndent(lines[i])
		if ind <= propIndent && strings.TrimSpace(lines[i]) != "" {
			break
		}
		if ind == expectedIndent {
			trimmed := strings.TrimSpace(lines[i])
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) >= 1 {
				key := strings.TrimSpace(parts[0])
				if key != "" {
					keys = append(keys, key)
				}
			}
		}
	}
	return keys
}

// --- Locals context analysis (YAML) ---

// analyzeLocalsContext checks if the cursor is inside a Locals block (YAML)
// and returns the appropriate context for local variable property or type value completion.
func analyzeLocalsContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	if !isInsideSection(lines, line, indent, "Locals") {
		return nil
	}

	// Check if inside the Properties sub-block of a local variable first,
	// because findLocalsContext would misidentify "Properties" as the local name.
	if propsCtx := analyzeLocalsPropertiesContext(lines, line, col, currentLine, indent); propsCtx != nil {
		return propsCtx
	}

	localName, found := findLocalsContext(lines, line, indent)
	if !found {
		return nil
	}

	trimmed := strings.TrimSpace(currentLine)

	// Type: value → suggest Macro, Eval, DATASOURCE types
	if strings.HasPrefix(trimmed, "Type:") {
		colonPos := strings.Index(currentLine, ":")
		if colonPos >= 0 && col > colonPos {
			return &AnalysisContext{
				Type:          ContextLocalsTypeValue,
				Prefix:        extractValuePrefix(currentLine, col),
				ValueStartCol: findValueStartCol(currentLine),
			}
		}
	}

	// On the same line as "Value:" with cursor after the colon → intrinsic functions
	if strings.HasPrefix(trimmed, "Value:") {
		colonPos := strings.Index(currentLine, ":")
		if colonPos >= 0 && col > colonPos {
			return &AnalysisContext{
				Type:   ContextPropertyValue,
				Prefix: extractValuePrefix(currentLine, col),
			}
		}
	}

	// On a nested line under "Value:" → intrinsic functions
	valueIndent := findParentKeyIndent(lines, line, indent, "Value")
	if valueIndent >= 0 && indent > valueIndent {
		return &AnalysisContext{
			Type:   ContextPropertyValue,
			Prefix: extractPropertyValuePrefix(currentLine, col, ""),
		}
	}

	return &AnalysisContext{
		Type:         ContextLocalsBlock,
		ResourceName: localName,
		Prefix:       extractPrefix(currentLine, col),
		ExistingKeys: findExistingLocalsAttrs(lines, line, indent),
	}
}

// analyzeLocalsPropertiesContext checks if the cursor is inside a Properties
// sub-block of a local variable. When a local has a DATASOURCE type, the
// Properties block should offer resource property completions.
func analyzeLocalsPropertiesContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	propsIndent := -1
	localName := ""
	tempIndent := indent

	for i := line; i >= 0; i-- {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		li := countIndent(l)

		if li == 0 {
			break
		}

		if li < tempIndent {
			key := strings.SplitN(lt, ":", 2)[0]
			key = strings.TrimSpace(key)

			if propsIndent < 0 {
				if key == "Properties" {
					propsIndent = li
					tempIndent = li
					continue
				}
				return nil
			}
			localName = key
			break
		}
	}

	if propsIndent < 0 || localName == "" {
		return nil
	}

	localType := findLocalTypeYAML(lines, line, localName)
	if localType == "" {
		return nil
	}

	propName := findPropertyName(lines, line, propsIndent)
	if propName != "" && indent > propsIndent+2 {
		return &AnalysisContext{
			Type:             ContextPropertyValue,
			ResourceName:     localName,
			ResourceTypeName: localType,
			PropertyName:     propName,
			Prefix:           extractPropertyValuePrefix(currentLine, col, propName),
		}
	}

	return &AnalysisContext{
		Type:             ContextResourceProperties,
		ResourceName:     localName,
		ResourceTypeName: localType,
		Prefix:           extractPrefix(currentLine, col),
		ExistingKeys:     findExistingProperties(lines, line),
	}
}

// findLocalTypeYAML finds the Type value of a local variable by searching
// its children for a Type: key.
func findLocalTypeYAML(lines []string, fromLine int, localName string) string {
	localLine := -1
	localIndent := -1
	for i := fromLine; i >= 0; i-- {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		ind := countIndent(l)
		if ind == 0 {
			break
		}
		if strings.HasPrefix(lt, localName+":") || lt == localName {
			localLine = i
			localIndent = ind
			break
		}
	}
	if localLine < 0 {
		return ""
	}

	for i := localLine + 1; i < len(lines); i++ {
		l := lines[i]
		lt := strings.TrimSpace(l)
		if lt == "" {
			continue
		}
		ind := countIndent(l)
		if ind <= localIndent {
			break
		}
		if ind == localIndent+2 && strings.HasPrefix(lt, "Type:") {
			parts := strings.SplitN(lt, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// findLocalsContext walks backwards from the current line to determine if
// the cursor is inside a Locals block. Returns the local variable name and
// whether a valid locals context was found.
func findLocalsContext(lines []string, currentLine, currentIndent int) (localName string, found bool) {
	tempIndent := currentIndent

	for i := currentLine; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		ind := countIndent(line)

		if ind == 0 {
			if strings.HasPrefix(trimmed, "Locals:") || trimmed == "Locals" {
				return localName, localName != ""
			}
			return "", false
		}

		if ind < tempIndent && localName == "" {
			key := strings.SplitN(trimmed, ":", 2)[0]
			localName = strings.TrimSpace(key)
			tempIndent = ind
		}
	}
	return "", false
}

// findExistingLocalsAttrs collects the existing attribute keys under a
// local variable definition (sibling keys at the same indentation level).
func findExistingLocalsAttrs(lines []string, currentLine, currentIndent int) []string {
	parentLine := -1
	for i := currentLine - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		ind := countIndent(lines[i])
		if ind < currentIndent {
			parentLine = i
			break
		}
	}

	if parentLine < 0 {
		return nil
	}

	parentIndent := countIndent(lines[parentLine])

	var keys []string
	for i := parentLine + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		ind := countIndent(lines[i])
		if ind <= parentIndent {
			break
		}
		if ind == currentIndent {
			trimmed := strings.TrimSpace(lines[i])
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) >= 1 {
				key := strings.TrimSpace(parts[0])
				if key != "" {
					keys = append(keys, key)
				}
			}
		}
	}
	return keys
}

// --- Conditions context analysis (YAML) ---

// analyzeConditionsContext checks if the cursor is inside a Conditions block (YAML).
func analyzeConditionsContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	if !isInsideSection(lines, line, indent, "Conditions") {
		return nil
	}
	return &AnalysisContext{
		Type:   ContextConditionsBlock,
		Prefix: extractPropertyValuePrefix(currentLine, col, ""),
	}
}

// analyzeConditionValueContext checks if the cursor is at a Condition: value
// in a Resource or Output block (YAML). Returns ContextConditionValue if so.
func analyzeConditionValueContext(lines []string, line, col int, currentLine string) *AnalysisContext {
	trimmed := strings.TrimSpace(currentLine)
	if strings.HasPrefix(trimmed, "Condition:") {
		colonIdx := strings.Index(currentLine, ":")
		if colonIdx >= 0 && col > colonIdx {
			prefix := ""
			if col > colonIdx+1 && col <= len(currentLine) {
				prefix = strings.TrimSpace(currentLine[colonIdx+1 : col])
			}
			return &AnalysisContext{
				Type:   ContextConditionValue,
				Prefix: prefix,
			}
		}
	}
	return nil
}

// --- Condition function context analysis (YAML) ---

// checkConditionFnContext detects if the cursor is at a condition-name argument
// of Fn::If, Fn::And, Fn::Or, or Fn::Not (YAML).
func checkConditionFnContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)
	indent := countIndent(currentLine)

	for _, fn := range conditionFns {
		// Short form: !If [...], !And [...], !Or [...], !Not [...]
		shortTag := fn.shortForm + " "
		shortIdx := strings.Index(currentLine, shortTag)
		if shortIdx >= 0 && col >= shortIdx+len(shortTag) {
			return parseConditionFnShortForm(currentLine, shortIdx+len(shortTag), col, fn.allArgs)
		}
		if strings.HasSuffix(trimmed, fn.shortForm) {
			tagPos := strings.Index(currentLine, fn.shortForm)
			if col >= tagPos+len(fn.shortForm) {
				return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: ""}
			}
		}

		// Long form: list items under "Fn::If:", "Fn::And:", etc.
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			longPrefix := fn.longForm + ":"
			for i := line - 1; i >= 0; i-- {
				l := strings.TrimSpace(lines[i])
				li := countIndent(lines[i])
				if li < indent {
					if strings.HasPrefix(l, longPrefix) || l == fn.longForm {
						if fn.allArgs {
							prefix := extractListItemPrefix(currentLine, col)
							return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: prefix}
						}
						itemIndex := 0
						for j := i + 1; j <= line; j++ {
							jl := strings.TrimSpace(lines[j])
							if strings.HasPrefix(jl, "- ") || jl == "-" {
								itemIndex++
							}
						}
						if itemIndex == 1 {
							prefix := extractListItemPrefix(currentLine, col)
							return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: prefix}
						}
					}
					break
				}
			}
		}
	}

	return nil
}

// extractListItemPrefix extracts the prefix text after "- " at the cursor position.
func extractListItemPrefix(currentLine string, col int) string {
	dashIdx := strings.Index(currentLine, "-")
	if dashIdx >= 0 && col > dashIdx+2 && col <= len(currentLine) {
		return strings.TrimSpace(currentLine[dashIdx+2 : col])
	}
	return ""
}

// parseConditionFnShortForm parses the short form !If/!And/!Or/!Not [args...] and returns
// ContextFnIfConditionName if the cursor is at a condition-name argument position.
func parseConditionFnShortForm(line string, argsStart, col int, allArgs bool) *AnalysisContext {
	if col < argsStart || col > len(line) {
		return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: ""}
	}
	argsPart := line[argsStart:col]
	argsPart = strings.TrimLeft(argsPart, "[ ")

	parts := strings.Split(argsPart, ",")
	if allArgs {
		prefix := strings.TrimSpace(parts[len(parts)-1])
		return &AnalysisContext{Type: ContextFnIfConditionName, Prefix: prefix}
	}
	if len(parts) <= 1 {
		return &AnalysisContext{
			Type:   ContextFnIfConditionName,
			Prefix: strings.TrimSpace(parts[0]),
		}
	}
	return nil
}

// --- Mappings and FindInMap context analysis (YAML) ---

// analyzeMappingsContext checks if the cursor is inside a Mappings block (YAML).
func analyzeMappingsContext(lines []string, line, col int, currentLine string, indent int) *AnalysisContext {
	if !isInsideSection(lines, line, indent, "Mappings") {
		return nil
	}
	return &AnalysisContext{Type: ContextMappingsBlock}
}

// checkFindInMapContext detects if the cursor is in a Fn::FindInMap / !FindInMap parameter position (YAML).
func checkFindInMapContext(lines []string, line, col int) *AnalysisContext {
	currentLine := lines[line]
	trimmed := strings.TrimSpace(currentLine)
	indent := countIndent(currentLine)

	// Short form: !FindInMap [mapName, firstKey, secondKey]
	fimIdx := strings.Index(currentLine, "!FindInMap ")
	if fimIdx >= 0 && col >= fimIdx+11 {
		return parseFindInMapShortForm(currentLine, fimIdx+11, col)
	}
	if strings.HasSuffix(trimmed, "!FindInMap") {
		fimPos := strings.Index(currentLine, "!FindInMap")
		if col >= fimPos+10 {
			return &AnalysisContext{Type: ContextFindInMapMapName, Prefix: ""}
		}
	}

	// Long form: list items under "Fn::FindInMap:"
	if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
		for i := line - 1; i >= 0; i-- {
			l := strings.TrimSpace(lines[i])
			li := countIndent(lines[i])
			if li < indent {
				if strings.HasPrefix(l, "Fn::FindInMap:") || l == "Fn::FindInMap" {
					itemIndex := 0
					var items []string
					for j := i + 1; j <= line; j++ {
						jl := strings.TrimSpace(lines[j])
						if strings.HasPrefix(jl, "- ") || jl == "-" {
							if j < line {
								items = append(items, strings.TrimSpace(strings.TrimPrefix(jl, "- ")))
							}
							itemIndex++
						}
					}
					prefix := ""
					dashIdx := strings.Index(currentLine, "-")
					if dashIdx >= 0 && col > dashIdx+2 && col <= len(currentLine) {
						prefix = strings.TrimSpace(currentLine[dashIdx+2 : col])
					}
					switch {
					case itemIndex <= 1:
						return &AnalysisContext{Type: ContextFindInMapMapName, Prefix: prefix}
					case itemIndex == 2 && len(items) >= 1:
						return &AnalysisContext{
							Type:             ContextFindInMapFirstKey,
							FindInMapMapName: items[0],
							Prefix:           prefix,
						}
					case itemIndex >= 3 && len(items) >= 2:
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
	}

	// Inline long form: Fn::FindInMap: [mapName, firstKey, secondKey]
	if strings.Contains(currentLine, "Fn::FindInMap:") {
		colonIdx := strings.Index(currentLine, "Fn::FindInMap:") + 14
		if col >= colonIdx {
			afterColon := ""
			if col <= len(currentLine) {
				afterColon = currentLine[colonIdx:col]
			}
			bracketIdx := strings.Index(afterColon, "[")
			if bracketIdx >= 0 {
				return parseFindInMapShortForm(currentLine, colonIdx+bracketIdx+1, col)
			}
		}
	}

	return nil
}

// parseFindInMapShortForm parses the [mapName, firstKey, secondKey] inline form.
func parseFindInMapShortForm(line string, argsStart, col int) *AnalysisContext {
	if col < argsStart || col > len(line) {
		return &AnalysisContext{Type: ContextFindInMapMapName, Prefix: ""}
	}
	argsPart := line[argsStart:col]
	argsPart = strings.TrimLeft(argsPart, "[ ")

	parts := strings.Split(argsPart, ",")
	switch len(parts) {
	case 1:
		return &AnalysisContext{
			Type:   ContextFindInMapMapName,
			Prefix: strings.TrimSpace(parts[0]),
		}
	case 2:
		return &AnalysisContext{
			Type:             ContextFindInMapFirstKey,
			FindInMapMapName: strings.TrimSpace(parts[0]),
			Prefix:           strings.TrimSpace(parts[1]),
		}
	default:
		return &AnalysisContext{
			Type:              ContextFindInMapSecondKey,
			FindInMapMapName:  strings.TrimSpace(parts[0]),
			FindInMapFirstKey: strings.TrimSpace(parts[1]),
			Prefix:            strings.TrimSpace(parts[len(parts)-1]),
		}
	}
}
