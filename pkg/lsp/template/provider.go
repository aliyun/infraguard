package template

import (
	"fmt"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
)

// FormatHandler encapsulates format-specific operations for YAML and JSON templates.
// Adding a new format requires implementing all methods, ensuring parity between formats.
type FormatHandler interface {
	ParseTemplate(content string) *ParsedTemplate

	BuildTopLevelSnippet(item *protocol.CompletionItem, blockName string, ctx CompletionContext)
	BuildTypeCompletion(item *protocol.CompletionItem, name string, analysis *AnalysisContext, ctx CompletionContext, lines []string, hasProps bool)
	BuildPropertyCompletion(item *protocol.CompletionItem, name string, ctx CompletionContext)
	BuildResourceBlockSnippet(item *protocol.CompletionItem, blockName string, analysis *AnalysisContext, ctx CompletionContext)
	BuildOutputBlockSnippet(item *protocol.CompletionItem, blockName string, ctx CompletionContext)
	BuildParameterPropertySnippet(item *protocol.CompletionItem, prop ROSParameterProperty, ctx CompletionContext)
	BuildParameterTypeValueSnippet(item *protocol.CompletionItem, typeName string, analysis *AnalysisContext, ctx CompletionContext)
	BuildLocalsPropertySnippet(item *protocol.CompletionItem, prop ROSLocalsProperty, ctx CompletionContext)
	BuildLocalsTypeValueSnippet(item *protocol.CompletionItem, typeName string, analysis *AnalysisContext, ctx CompletionContext)
	BuildAssociationPropertyValueSnippet(item *protocol.CompletionItem, name string, analysis *AnalysisContext, ctx CompletionContext)
	BuildAssociationPropertyMetadataKeySnippet(item *protocol.CompletionItem, key string, ctx CompletionContext)
	BuildIntrinsicFunctionSnippet(item *protocol.CompletionItem, fn IntrinsicFunction, isShortTag bool, ctx CompletionContext)
	HasShortTags() bool

	FindKeyLine(content, key string) int
	FindParameterRange(content, paramName string) protocol.Range
	FindParameterAttrValueRange(content, paramName, attrName string) protocol.Range
	FindResourceRange(content, resName string) protocol.Range
	FindResourceTypeRange(content, resName string) protocol.Range
	FindResourcePropertyValueRange(content, resName, propName string) protocol.Range
	FindLocalsRange(content, localName string) protocol.Range
	FindMappingsRange(content, mapName string) protocol.Range
	FindConditionsRange(content, condName string) protocol.Range
	FindConditionValueRange(content, section, entryName string) protocol.Range

	ExtractKeyFromLine(line string) string
	ExtractValueFromLine(line string) string

	ValidateFormat(ctx ValidationContext) []protocol.Diagnostic
}

func getFormatHandler(isYAML bool) FormatHandler {
	if isYAML {
		return &yamlFormatHandler{}
	}
	return &jsonFormatHandler{}
}

// CompletionContext holds context for generating completions.
type CompletionContext struct {
	URI      string
	Content  string
	Line     int
	Col      int
	IsYAML   bool
	Registry *schema.Registry
}

// HoverContext holds context for generating hover content.
type HoverContext struct {
	URI      string
	Content  string
	Line     int
	Col      int
	IsYAML   bool
	Registry *schema.Registry
}

// ValidationContext holds context for validation.
type ValidationContext struct {
	URI      string
	Content  string
	IsYAML   bool
	Registry *schema.Registry
}

// HoverResult holds the result of a hover request.
type HoverResult struct {
	Contents string
	Range    *protocol.Range
}

// TemplateProvider defines the interface for template-specific LSP support.
type TemplateProvider interface {
	Detect(content []byte, filename string) bool
	Complete(ctx CompletionContext) []protocol.CompletionItem
	Hover(ctx HoverContext) *HoverResult
	Validate(ctx ValidationContext) []protocol.Diagnostic
}

// ROSTemplateProvider implements TemplateProvider for ROS templates.
type ROSTemplateProvider struct{}

// Detect checks if the content is a ROS template.
func (p *ROSTemplateProvider) Detect(content []byte, filename string) bool {
	if strings.HasSuffix(filename, ".ros.yaml") || strings.HasSuffix(filename, ".ros.yml") || strings.HasSuffix(filename, ".ros.json") {
		return true
	}
	return strings.Contains(string(content), "ROSTemplateFormatVersion")
}

// Complete returns completion items for the given context.
func (p *ROSTemplateProvider) Complete(ctx CompletionContext) []protocol.CompletionItem {
	analysis := AnalyzePosition(ctx.Content, ctx.Line, ctx.Col, ctx.IsYAML)
	handler := getFormatHandler(ctx.IsYAML)

	switch analysis.Type {
	case ContextTopLevel:
		return p.completeTopLevel(analysis, handler, ctx)
	case ContextResourceType:
		return p.completeResourceType(analysis, handler, ctx)
	case ContextResourceProperties:
		return p.completeResourceProperties(analysis, handler, ctx)
	case ContextPropertyValue:
		return p.completePropertyValue(analysis, handler, ctx)
	case ContextResourceBlock:
		return p.completeResourceBlock(analysis, handler, ctx)
	case ContextOutputBlock:
		return p.completeOutputBlock(analysis, handler, ctx)
	case ContextRefValue:
		return p.completeRefValue(analysis, handler, ctx)
	case ContextGetAttResource:
		return p.completeGetAttResource(analysis, handler, ctx)
	case ContextGetAttAttribute:
		return p.completeGetAttAttribute(analysis, handler, ctx)
	case ContextParameterProperties:
		return p.completeParameterProperties(analysis, handler, ctx)
	case ContextParameterTypeValue:
		return p.completeParameterTypeValue(analysis, handler, ctx)
	case ContextAssociationPropertyValue:
		return p.completeAssociationPropertyValue(analysis, handler, ctx)
	case ContextAssociationPropertyMetadataKey:
		return p.completeAssociationPropertyMetadataKey(analysis, handler, ctx)
	case ContextLocalsBlock:
		return p.completeLocalsProperties(analysis, handler, ctx)
	case ContextLocalsTypeValue:
		return p.completeLocalsTypeValue(analysis, handler, ctx)
	case ContextMappingsBlock:
		return p.completeMappingsBlock(analysis, handler, ctx)
	case ContextFindInMapMapName:
		return p.completeFindInMapMapName(analysis, handler, ctx)
	case ContextFindInMapFirstKey:
		return p.completeFindInMapFirstKey(analysis, handler, ctx)
	case ContextFindInMapSecondKey:
		return p.completeFindInMapSecondKey(analysis, handler, ctx)
	case ContextConditionsBlock:
		return p.completeConditionsBlock(analysis, handler, ctx)
	case ContextConditionValue:
		return p.completeConditionValue(analysis, handler, ctx)
	case ContextFnIfConditionName:
		return p.completeConditionValue(analysis, handler, ctx)
	default:
		return nil
	}
}

// Hover returns hover information for the given context.
func (p *ROSTemplateProvider) Hover(ctx HoverContext) *HoverResult {
	analysis := AnalyzePosition(ctx.Content, ctx.Line, ctx.Col, ctx.IsYAML)
	handler := getFormatHandler(ctx.IsYAML)

	lines := strings.Split(ctx.Content, "\n")
	if ctx.Line < 0 || ctx.Line >= len(lines) {
		return nil
	}
	currentLine := lines[ctx.Line]

	switch analysis.Type {
	case ContextTopLevel:
		return p.hoverTopLevel(currentLine, handler)
	case ContextResourceType:
		return p.hoverResourceType(currentLine, handler, ctx)
	case ContextResourceProperties:
		return p.hoverResourceProperty(currentLine, handler, analysis, ctx)
	case ContextResourceBlock:
		return p.hoverResourceBlock(currentLine, handler)
	case ContextParameterProperties:
		return p.hoverParameterProperty(currentLine, handler)
	case ContextParameterTypeValue:
		return p.hoverParameterTypeValue(currentLine, handler)
	case ContextAssociationPropertyValue:
		return p.hoverAssociationPropertyValue(currentLine, handler, ctx)
	case ContextLocalsBlock:
		return p.hoverLocalsProperty(currentLine, handler)
	case ContextLocalsTypeValue:
		return p.hoverLocalsTypeValue(currentLine, handler)
	case ContextMappingsBlock:
		return p.hoverMappingsBlock(currentLine, handler)
	default:
		return p.hoverIntrinsicFunction(currentLine)
	}
}

// Validate returns diagnostics for the given context.
func (p *ROSTemplateProvider) Validate(ctx ValidationContext) []protocol.Diagnostic {
	handler := getFormatHandler(ctx.IsYAML)
	pt := handler.ParseTemplate(ctx.Content)

	var diags []protocol.Diagnostic

	diags = append(diags, handler.ValidateFormat(ctx)...)

	if pt.Root == nil {
		return diags
	}

	diags = append(diags, p.validateFormatVersion(pt, handler, ctx)...)
	diags = append(diags, p.validateTopLevelKeys(pt, handler, ctx)...)
	diags = append(diags, p.validateParameters(pt, handler, ctx)...)
	diags = append(diags, p.validateLocals(pt, handler, ctx)...)
	diags = append(diags, p.validateResources(pt, handler, ctx)...)
	diags = append(diags, p.validateMappings(pt, handler, ctx)...)
	diags = append(diags, p.validateConditions(pt, handler, ctx)...)
	diags = append(diags, p.validateConditionRefs(pt, handler, ctx)...)

	return diags
}

// --- Completion implementations ---

func (p *ROSTemplateProvider) completeTopLevel(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	existing := make(map[string]bool)
	for _, k := range analysis.ExistingKeys {
		existing[k] = true
	}

	prefix := strings.ToLower(analysis.Prefix)
	filterByPrefix := prefix != ""

	var items []protocol.CompletionItem
	for i, block := range ROSTopLevelBlocks {
		if existing[block.Name] {
			continue
		}
		if filterByPrefix && !strings.HasPrefix(strings.ToLower(block.Name), prefix) {
			continue
		}
		item := protocol.CompletionItem{
			Label:  block.Name,
			Kind:   protocol.CompletionItemKindKeyword,
			Detail: block.Description,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: block.Description,
			},
			SortText: sortKey(i),
		}
		handler.BuildTopLevelSnippet(&item, block.Name, ctx)
		items = append(items, item)
	}
	return items
}

func (p *ROSTemplateProvider) completeResourceType(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	var names []string
	if analysis.Prefix != "" {
		names = ctx.Registry.SearchResourceTypes(analysis.Prefix)
	} else {
		names = ctx.Registry.AllResourceTypeNames()
	}

	lines := strings.Split(ctx.Content, "\n")
	hasProps := HasPropertiesSection(ctx.Content, ctx.Line)

	items := make([]protocol.CompletionItem, 0, len(names))
	for i, name := range names {
		rt := ctx.Registry.GetResourceType(name)
		detail := ""
		if rt != nil {
			detail = rt.Description
		}

		item := protocol.CompletionItem{
			Label:      name,
			Kind:       protocol.CompletionItemKindClass,
			Detail:     detail,
			FilterText: name,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: detail,
			},
			SortText: sortKey(i),
		}

		handler.BuildTypeCompletion(&item, name, analysis, ctx, lines, hasProps)
		items = append(items, item)
	}
	return items
}

func (p *ROSTemplateProvider) completeResourceProperties(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	if analysis.ResourceTypeName == "" {
		return nil
	}

	props := ctx.Registry.GetProperties(analysis.ResourceTypeName)
	if props == nil {
		return nil
	}

	existing := make(map[string]bool)
	for _, k := range analysis.ExistingKeys {
		existing[k] = true
	}

	var items []protocol.CompletionItem
	sortIdx := 0
	for name, prop := range props {
		if existing[name] || !prop.Required {
			continue
		}
		detail := formatPropertyDetail(prop, true)
		item := protocol.CompletionItem{
			Label:            name,
			Kind:             protocol.CompletionItemKindProperty,
			Detail:           detail,
			InsertTextFormat: protocol.InsertTextFormatSnippet,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: formatPropertyDoc(name, prop),
			},
			SortText: sortKey(sortIdx),
		}
		handler.BuildPropertyCompletion(&item, name, ctx)
		items = append(items, item)
		sortIdx++
	}
	for name, prop := range props {
		if existing[name] || prop.Required {
			continue
		}
		detail := formatPropertyDetail(prop, false)
		item := protocol.CompletionItem{
			Label:            name,
			Kind:             protocol.CompletionItemKindProperty,
			Detail:           detail,
			InsertTextFormat: protocol.InsertTextFormatSnippet,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: formatPropertyDoc(name, prop),
			},
			SortText: sortKey(sortIdx),
		}
		handler.BuildPropertyCompletion(&item, name, ctx)
		items = append(items, item)
		sortIdx++
	}
	return items
}

func (p *ROSTemplateProvider) completePropertyValue(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	if analysis.Prefix != "" && !strings.HasPrefix(analysis.Prefix, "!") && !isIntrinsicFunctionPrefix(analysis.Prefix) {
		return nil
	}
	return p.completeIntrinsicFunctions(handler, ctx)
}

func isIntrinsicFunctionPrefix(prefix string) bool {
	lower := strings.ToLower(prefix)
	for _, fn := range ROSIntrinsicFunctions {
		if strings.HasPrefix(strings.ToLower(fn.Name), lower) {
			return true
		}
	}
	return false
}

func (p *ROSTemplateProvider) completeRefValue(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	pt := handler.ParseTemplate(ctx.Content)
	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	for _, paramName := range pt.GetParameterNames() {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(paramName), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:    paramName,
			Kind:     protocol.CompletionItemKindVariable,
			Detail:   "Parameter",
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	for _, localName := range pt.GetLocalsNames() {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(localName), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:    localName,
			Kind:     protocol.CompletionItemKindVariable,
			Detail:   "Local",
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	for _, resName := range pt.GetResourceNames() {
		if resName == analysis.ResourceName {
			continue
		}
		if prefix != "" && !strings.HasPrefix(strings.ToLower(resName), prefix) {
			continue
		}
		resType := pt.GetResourceType(resName)
		detail := "Resource"
		if resType != "" {
			detail = resType
		}
		items = append(items, protocol.CompletionItem{
			Label:    resName,
			Kind:     protocol.CompletionItemKindValue,
			Detail:   detail,
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	for _, pp := range ROSPseudoParameters {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(pp.Name), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:    pp.Name,
			Kind:     protocol.CompletionItemKindConstant,
			Detail:   pp.Description,
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeGetAttResource(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	pt := handler.ParseTemplate(ctx.Content)
	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	for _, resName := range pt.GetResourceNames() {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(resName), prefix) {
			continue
		}
		resType := pt.GetResourceType(resName)
		detail := "Resource"
		if resType != "" {
			detail = resType
		}
		items = append(items, protocol.CompletionItem{
			Label:    resName,
			Kind:     protocol.CompletionItemKindValue,
			Detail:   detail,
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeGetAttAttribute(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	if analysis.GetAttResourceName == "" {
		return nil
	}

	pt := handler.ParseTemplate(ctx.Content)
	resType := pt.GetResourceType(analysis.GetAttResourceName)
	if resType == "" {
		return nil
	}

	attrs := ctx.Registry.GetAttributes(resType)
	if attrs == nil {
		return nil
	}

	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	for attrName, attr := range attrs {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(attrName), prefix) {
			continue
		}
		detail := attr.Description
		items = append(items, protocol.CompletionItem{
			Label:    attrName,
			Kind:     protocol.CompletionItemKindProperty,
			Detail:   detail,
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeResourceBlock(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	blockKeys := []struct {
		Name string
		Desc string
	}{
		{"Type", "The resource type"},
		{"Properties", "Resource properties"},
		{"DependsOn", "Resource dependencies"},
		{"DeletionPolicy", "Deletion policy (Delete, Retain, Snapshot)"},
		{"Metadata", "Resource metadata"},
		{"Condition", "Condition for resource creation"},
		{"Count", "Number of resource instances to create"},
	}

	prefix := strings.ToLower(analysis.Prefix)
	filterByPrefix := prefix != ""

	var items []protocol.CompletionItem
	for i, bk := range blockKeys {
		if filterByPrefix && !strings.HasPrefix(strings.ToLower(bk.Name), prefix) {
			continue
		}
		item := protocol.CompletionItem{
			Label:    bk.Name,
			Kind:     protocol.CompletionItemKindKeyword,
			Detail:   bk.Desc,
			SortText: sortKey(i),
		}
		handler.BuildResourceBlockSnippet(&item, bk.Name, analysis, ctx)
		items = append(items, item)
	}
	return items
}

func (p *ROSTemplateProvider) completeOutputBlock(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	outputKeys := []struct {
		Name     string
		Desc     string
		Required bool
	}{
		{"Value", "The value returned by the output (required)", true},
		{"Description", "A description of the output value", false},
		{"Condition", "Condition for including this output", false},
	}

	existing := make(map[string]bool)
	for _, k := range analysis.ExistingKeys {
		existing[k] = true
	}

	prefix := strings.ToLower(analysis.Prefix)
	filterByPrefix := prefix != ""

	var items []protocol.CompletionItem
	for i, ok := range outputKeys {
		if existing[ok.Name] {
			continue
		}
		if filterByPrefix && !strings.HasPrefix(strings.ToLower(ok.Name), prefix) {
			continue
		}
		detail := ok.Desc
		if ok.Required {
			detail += " *"
		}
		item := protocol.CompletionItem{
			Label:    ok.Name,
			Kind:     protocol.CompletionItemKindKeyword,
			Detail:   detail,
			SortText: sortKey(i),
		}
		handler.BuildOutputBlockSnippet(&item, ok.Name, ctx)
		items = append(items, item)
	}
	return items
}

func (p *ROSTemplateProvider) completeParameterProperties(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	existing := make(map[string]bool)
	for _, k := range analysis.ExistingKeys {
		existing[k] = true
	}

	prefix := strings.ToLower(analysis.Prefix)
	filterByPrefix := prefix != ""

	var items []protocol.CompletionItem
	sortIdx := 0

	for _, prop := range ROSParameterProperties {
		if existing[prop.Name] {
			continue
		}
		if filterByPrefix && !strings.HasPrefix(strings.ToLower(prop.Name), prefix) {
			continue
		}
		detail := prop.Description
		if prop.Required {
			detail += " *"
		}
		item := protocol.CompletionItem{
			Label:  prop.Name,
			Kind:   protocol.CompletionItemKindProperty,
			Detail: detail,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: formatParameterPropertyDoc(prop),
			},
			SortText: sortKey(sortIdx),
		}
		handler.BuildParameterPropertySnippet(&item, prop, ctx)
		items = append(items, item)
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeParameterTypeValue(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	prefix := strings.Trim(strings.ToLower(analysis.Prefix), "'\"")
	var items []protocol.CompletionItem

	for i, t := range ROSParameterTypeValues {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(t.Name), prefix) {
			continue
		}
		item := protocol.CompletionItem{
			Label:  t.Name,
			Kind:   protocol.CompletionItemKindEnumMember,
			Detail: t.Description,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: "**" + t.Name + "**\n\n" + t.Description,
			},
			SortText: sortKey(i),
		}
		handler.BuildParameterTypeValueSnippet(&item, t.Name, analysis, ctx)
		items = append(items, item)
	}

	return items
}

func (p *ROSTemplateProvider) completeAssociationPropertyValue(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	prefix := strings.Trim(strings.ToLower(analysis.Prefix), "'\"")
	var items []protocol.CompletionItem

	names := ctx.Registry.AllAssociationPropertyNames()
	for i, name := range names {
		if prefix != "" && !strings.Contains(strings.ToLower(name), prefix) {
			continue
		}
		ap := ctx.Registry.GetAssociationProperty(name)
		detail := ""
		if ap != nil {
			detail = ap.Description
		}
		doc := formatAssociationPropertyDoc(name, ap)
		item := protocol.CompletionItem{
			Label:  name,
			Kind:   protocol.CompletionItemKindEnumMember,
			Detail: detail,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: doc,
			},
			SortText: sortKey(i),
		}
		handler.BuildAssociationPropertyValueSnippet(&item, name, analysis, ctx)
		items = append(items, item)
	}

	return items
}

func (p *ROSTemplateProvider) completeAssociationPropertyMetadataKey(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	assocPropName := analysis.ResourceTypeName
	if assocPropName == "" {
		return nil
	}

	ap := ctx.Registry.GetAssociationProperty(assocPropName)
	if ap == nil || len(ap.Metadata) == 0 {
		return nil
	}

	existing := make(map[string]bool)
	for _, k := range analysis.ExistingKeys {
		existing[k] = true
	}

	var items []protocol.CompletionItem
	sortIdx := 0

	for key, meta := range ap.Metadata {
		if existing[key] {
			continue
		}
		detail := meta.Description
		item := protocol.CompletionItem{
			Label:      key,
			Kind:       protocol.CompletionItemKindProperty,
			Detail:     detail,
			FilterText: key,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: fmt.Sprintf("**%s**\n\n%s\n\n*AssociationProperty: %s*", key, detail, assocPropName),
			},
			SortText: sortKey(sortIdx),
		}
		handler.BuildAssociationPropertyMetadataKeySnippet(&item, key, ctx)
		items = append(items, item)
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeLocalsProperties(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	existing := make(map[string]bool)
	for _, k := range analysis.ExistingKeys {
		existing[k] = true
	}

	prefix := strings.ToLower(analysis.Prefix)
	filterByPrefix := prefix != ""

	var items []protocol.CompletionItem
	sortIdx := 0

	for _, prop := range ROSLocalsProperties {
		if existing[prop.Name] {
			continue
		}
		if filterByPrefix && !strings.HasPrefix(strings.ToLower(prop.Name), prefix) {
			continue
		}
		detail := prop.Description
		if prop.Required {
			detail += " *"
		}
		item := protocol.CompletionItem{
			Label:  prop.Name,
			Kind:   protocol.CompletionItemKindProperty,
			Detail: detail,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: formatLocalsPropertyDoc(prop),
			},
			SortText: sortKey(sortIdx),
		}
		handler.BuildLocalsPropertySnippet(&item, prop, ctx)
		items = append(items, item)
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeLocalsTypeValue(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	prefix := strings.Trim(strings.ToLower(analysis.Prefix), "'\"")
	var items []protocol.CompletionItem

	for i, t := range ROSLocalsTypeValues {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(t.Name), prefix) {
			continue
		}
		item := protocol.CompletionItem{
			Label:  t.Name,
			Kind:   protocol.CompletionItemKindEnumMember,
			Detail: t.Description,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: "**" + t.Name + "**\n\n" + t.Description,
			},
			SortText: sortKey(i),
		}
		handler.BuildLocalsTypeValueSnippet(&item, t.Name, analysis, ctx)
		items = append(items, item)
	}

	// Also suggest DATASOURCE types from the registry
	if ctx.Registry != nil {
		dsNames := ctx.Registry.SearchResourceTypes("DATASOURCE::")
		for i, name := range dsNames {
			if prefix != "" && !strings.Contains(strings.ToLower(name), prefix) {
				continue
			}
			rt := ctx.Registry.GetResourceType(name)
			detail := ""
			if rt != nil {
				detail = rt.Description
			}
			item := protocol.CompletionItem{
				Label:  name,
				Kind:   protocol.CompletionItemKindClass,
				Detail: detail,
				Documentation: &protocol.Markup{
					Kind:  protocol.MarkupKindMarkdown,
					Value: "**" + name + "**\n\n" + detail,
				},
				SortText: sortKey(len(ROSLocalsTypeValues) + i),
			}
			handler.BuildLocalsTypeValueSnippet(&item, name, analysis, ctx)
			items = append(items, item)
		}
	}

	return items
}

func (p *ROSTemplateProvider) completeConditionsBlock(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	return p.completeIntrinsicFunctions(handler, ctx)
}

func (p *ROSTemplateProvider) completeConditionValue(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	pt := handler.ParseTemplate(ctx.Content)
	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	for _, condName := range pt.GetConditionNames() {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(condName), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:    condName,
			Kind:     protocol.CompletionItemKindValue,
			Detail:   "Condition",
			SortText: sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeMappingsBlock(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	return p.completeIntrinsicFunctions(handler, ctx)
}

func (p *ROSTemplateProvider) completeFindInMapMapName(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	pt := handler.ParseTemplate(ctx.Content)
	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	for _, mapName := range pt.GetMappingNames() {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(mapName), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:      mapName,
			Kind:       protocol.CompletionItemKindValue,
			Detail:     "Mapping",
			FilterText: mapName,
			SortText:   sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeFindInMapFirstKey(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	pt := handler.ParseTemplate(ctx.Content)
	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	for _, key := range pt.GetMappingFirstKeys(analysis.FindInMapMapName) {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(key), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:      key,
			Kind:       protocol.CompletionItemKindValue,
			Detail:     fmt.Sprintf("Key in %s", analysis.FindInMapMapName),
			FilterText: key,
			SortText:   sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) completeFindInMapSecondKey(analysis *AnalysisContext, handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	pt := handler.ParseTemplate(ctx.Content)
	prefix := strings.ToLower(analysis.Prefix)
	var items []protocol.CompletionItem
	sortIdx := 0

	// Try exact first key match; fall back to all second-level keys
	// when the first key is dynamic (e.g. Ref, Fn::*)
	secondKeys := pt.GetMappingSecondKeys(analysis.FindInMapMapName, analysis.FindInMapFirstKey)
	if secondKeys == nil {
		secondKeys = pt.GetAllMappingSecondKeys(analysis.FindInMapMapName)
	}

	detail := fmt.Sprintf("Key in %s", analysis.FindInMapMapName)
	if analysis.FindInMapFirstKey != "" && secondKeys != nil && len(pt.GetMappingSecondKeys(analysis.FindInMapMapName, analysis.FindInMapFirstKey)) > 0 {
		detail = fmt.Sprintf("Key in %s.%s", analysis.FindInMapMapName, analysis.FindInMapFirstKey)
	}

	for _, key := range secondKeys {
		if prefix != "" && !strings.HasPrefix(strings.ToLower(key), prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:      key,
			Kind:       protocol.CompletionItemKindValue,
			Detail:     detail,
			FilterText: key,
			SortText:   sortKey(sortIdx),
		})
		sortIdx++
	}

	return items
}

func (p *ROSTemplateProvider) hoverMappingsBlock(line string, handler FormatHandler) *HoverResult {
	key := handler.ExtractKeyFromLine(line)
	if key != "" {
		return &HoverResult{
			Contents: "**" + key + "**\n\nMapping entry in Mappings section",
		}
	}
	return nil
}

func (p *ROSTemplateProvider) validateMappings(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	mappings := pt.GetMappings()
	if mappings == nil {
		return nil
	}

	var diags []protocol.Diagnostic

	for mapName, mapVal := range mappings {
		firstLevel, ok := mapVal.(map[string]interface{})
		if !ok {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.MappingsInvalidStructure })
			if tmpl == "" {
				tmpl = "Mappings entry %q must be a two-level map"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindMappingsRange(ctx.Content, mapName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, mapName),
			})
			continue
		}

		for firstKey, secondVal := range firstLevel {
			if _, ok := secondVal.(map[string]interface{}); !ok {
				tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.MappingsInvalidStructure })
				if tmpl == "" {
					tmpl = "Mappings entry %q must be a two-level map"
				}
				diags = append(diags, protocol.Diagnostic{
					Range:    handler.FindMappingsRange(ctx.Content, mapName),
					Severity: protocol.DiagnosticSeverityWarning,
					Source:   "ros-lsp",
					Message:  fmt.Sprintf(tmpl, mapName+"."+firstKey),
				})
			}
		}
	}

	return diags
}

// ROSConditionFunctions lists the condition-defining functions.
var ROSConditionFunctions = map[string]bool{
	"Fn::Equals": true,
	"Fn::And":    true,
	"Fn::Or":     true,
	"Fn::Not":    true,
	"Fn::If":     true,
}

func (p *ROSTemplateProvider) validateConditions(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	conditions := pt.GetConditions()
	if conditions == nil {
		return nil
	}

	var diags []protocol.Diagnostic

	for condName, condVal := range conditions {
		if !isValidConditionExpression(condVal) {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.ConditionsInvalidExpression })
			if tmpl == "" {
				tmpl = "Condition %q must use a condition function (Fn::Equals, Fn::And, Fn::Or, Fn::Not)"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindConditionsRange(ctx.Content, condName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, condName),
			})
		}
	}

	return diags
}

func isValidConditionExpression(val interface{}) bool {
	m, ok := val.(map[string]interface{})
	if !ok {
		return false
	}
	for key := range m {
		if ROSConditionFunctions[key] {
			return true
		}
	}
	return false
}

func (p *ROSTemplateProvider) validateConditionRefs(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	conditionNames := make(map[string]bool)
	for _, name := range pt.GetConditionNames() {
		conditionNames[name] = true
	}

	var diags []protocol.Diagnostic

	checkSection := func(section string, entries map[string]interface{}) {
		for entryName, entryVal := range entries {
			entry, ok := entryVal.(map[string]interface{})
			if !ok {
				continue
			}
			condVal, hasCond := entry["Condition"]
			if !hasCond {
				continue
			}
			condStr, ok := condVal.(string)
			if !ok {
				continue
			}
			if !conditionNames[condStr] {
				tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.UndefinedCondition })
				if tmpl == "" {
					tmpl = "Undefined condition %q referenced in %s %q"
				}
				diags = append(diags, protocol.Diagnostic{
					Range:    handler.FindConditionValueRange(ctx.Content, section, entryName),
					Severity: protocol.DiagnosticSeverityWarning,
					Source:   "ros-lsp",
					Message:  fmt.Sprintf(tmpl, condStr, section, entryName),
				})
			}
		}
	}

	checkSection("Resources", pt.GetResources())
	if outputs, _ := pt.Root["Outputs"].(map[string]interface{}); outputs != nil {
		checkSection("Outputs", outputs)
	}

	return diags
}

func formatLocalsPropertyDoc(prop ROSLocalsProperty) string {
	var sb strings.Builder
	sb.WriteString("**" + prop.Name + "**\n\n")
	sb.WriteString("- **Type:** " + prop.ValueType + "\n")
	if prop.Required {
		sb.WriteString("- **Required:** Yes\n")
	} else {
		sb.WriteString("- **Required:** No\n")
	}
	sb.WriteString("\n" + prop.Description)
	return sb.String()
}

func formatAssociationPropertyDoc(name string, ap *schema.AssociationProperty) string {
	var sb strings.Builder
	sb.WriteString("**" + name + "**\n\n")
	if ap != nil {
		if ap.Category != "" {
			sb.WriteString("- **Category:** " + ap.Category + "\n")
		}
		sb.WriteString("\n" + ap.Description + "\n")
		if len(ap.Metadata) > 0 {
			sb.WriteString("\n**AssociationPropertyMetadata:**\n\n")
			for key, meta := range ap.Metadata {
				sb.WriteString("- `" + key + "`: " + meta.Description + "\n")
			}
		}
	}
	return sb.String()
}

func formatParameterPropertyDoc(prop ROSParameterProperty) string {
	var sb strings.Builder
	sb.WriteString("**" + prop.Name + "**\n\n")
	sb.WriteString("- **Type:** " + prop.ValueType + "\n")
	if prop.Required {
		sb.WriteString("- **Required:** Yes\n")
	} else {
		sb.WriteString("- **Required:** No\n")
	}
	sb.WriteString("\n" + prop.Description)
	return sb.String()
}

func (p *ROSTemplateProvider) completeIntrinsicFunctions(handler FormatHandler, ctx CompletionContext) []protocol.CompletionItem {
	var items []protocol.CompletionItem
	for i, fn := range ROSIntrinsicFunctions {
		if handler.HasShortTags() && fn.ShortTag != "" {
			item := protocol.CompletionItem{
				Label:  fn.ShortTag,
				Kind:   protocol.CompletionItemKindFunction,
				Detail: fn.Usage,
				Documentation: &protocol.Markup{
					Kind:  protocol.MarkupKindMarkdown,
					Value: "**" + fn.Name + "**\n\n" + fn.Usage + "\n\n```yaml\n" + fn.ParamFormat + "\n```",
				},
				SortText: sortKey(i),
			}
			handler.BuildIntrinsicFunctionSnippet(&item, fn, true, ctx)
			items = append(items, item)
		}
		item := protocol.CompletionItem{
			Label:  fn.Name,
			Kind:   protocol.CompletionItemKindFunction,
			Detail: fn.Usage,
			Documentation: &protocol.Markup{
				Kind:  protocol.MarkupKindMarkdown,
				Value: "**" + fn.Name + "**\n\n" + fn.Usage + "\n\n```yaml\n" + fn.ParamFormat + "\n```",
			},
			SortText: sortKey(100 + i),
		}
		handler.BuildIntrinsicFunctionSnippet(&item, fn, false, ctx)
		items = append(items, item)
	}

	return items
}

func formatPropertyDetail(prop *schema.Property, required bool) string {
	detail := prop.Type
	if required {
		detail += " *"
	}
	return detail
}

func formatPropertyDoc(name string, prop *schema.Property) string {
	var sb strings.Builder
	sb.WriteString("**" + name + "**\n\n")
	sb.WriteString("- **Type:** " + prop.Type + "\n")
	if prop.Required {
		sb.WriteString("- **Required:** Yes\n")
	} else {
		sb.WriteString("- **Required:** No\n")
	}
	if prop.Updatable {
		sb.WriteString("- **Updatable:** Yes\n")
	} else {
		sb.WriteString("- **Updatable:** No\n")
	}
	if prop.Description != "" {
		sb.WriteString("\n" + prop.Description)
	}
	return sb.String()
}

func sortKey(i int) string {
	return fmt.Sprintf("%05d", i)
}

// --- Hover implementations ---

func (p *ROSTemplateProvider) hoverTopLevel(line string, handler FormatHandler) *HoverResult {
	key := handler.ExtractKeyFromLine(line)

	for _, block := range ROSTopLevelBlocks {
		if block.Name == key {
			return &HoverResult{
				Contents: "**" + block.Name + "**\n\n" + block.Description,
			}
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverResourceType(line string, handler FormatHandler, ctx HoverContext) *HoverResult {
	typeName := handler.ExtractValueFromLine(line)
	typeName = strings.Trim(typeName, "'\"")

	if typeName == "" {
		return nil
	}

	rt := ctx.Registry.GetResourceType(typeName)
	if rt == nil {
		return nil
	}
	return &HoverResult{
		Contents: "**" + typeName + "**\n\n" + rt.Description,
	}
}

func (p *ROSTemplateProvider) hoverResourceProperty(line string, handler FormatHandler, analysis *AnalysisContext, ctx HoverContext) *HoverResult {
	propName := handler.ExtractKeyFromLine(line)

	if analysis.ResourceTypeName == "" {
		return nil
	}

	prop := ctx.Registry.GetProperty(analysis.ResourceTypeName, propName)
	if prop == nil {
		return nil
	}

	return &HoverResult{
		Contents: formatPropertyDoc(propName, prop),
	}
}

func (p *ROSTemplateProvider) hoverResourceBlock(line string, handler FormatHandler) *HoverResult {
	key := handler.ExtractKeyFromLine(line)

	descriptions := map[string]string{
		"Type":           "The resource type (e.g., ALIYUN::ECS::Instance, DATASOURCE::ECS::Instances, MODULE::MyModule)",
		"Properties":     "Resource configuration properties",
		"DependsOn":      "Resources that must be created before this resource",
		"DeletionPolicy": "Action to take when the resource is deleted (Delete, Retain, Snapshot)",
		"Metadata":       "Resource metadata",
		"Condition":      "Condition for resource creation",
		"Count":          "Number of resource instances to create",
	}

	if desc, ok := descriptions[key]; ok {
		return &HoverResult{
			Contents: "**" + key + "**\n\n" + desc,
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverParameterProperty(line string, handler FormatHandler) *HoverResult {
	key := handler.ExtractKeyFromLine(line)

	for _, prop := range ROSParameterProperties {
		if prop.Name == key {
			return &HoverResult{
				Contents: formatParameterPropertyDoc(prop),
			}
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverLocalsProperty(line string, handler FormatHandler) *HoverResult {
	key := handler.ExtractKeyFromLine(line)

	for _, prop := range ROSLocalsProperties {
		if prop.Name == key {
			return &HoverResult{
				Contents: formatLocalsPropertyDoc(prop),
			}
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverLocalsTypeValue(line string, handler FormatHandler) *HoverResult {
	typeName := handler.ExtractValueFromLine(line)
	typeName = strings.Trim(typeName, "'\"")

	for _, t := range ROSLocalsTypeValues {
		if t.Name == typeName {
			return &HoverResult{
				Contents: "**" + t.Name + "**\n\n" + t.Description,
			}
		}
	}
	if strings.HasPrefix(typeName, "DATASOURCE::") {
		return &HoverResult{
			Contents: "**" + typeName + "**\n\nDatasource resource type for querying cloud resource data",
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverParameterTypeValue(line string, handler FormatHandler) *HoverResult {
	typeName := handler.ExtractValueFromLine(line)
	typeName = strings.Trim(typeName, "'\"")

	for _, t := range ROSParameterTypeValues {
		if t.Name == typeName {
			return &HoverResult{
				Contents: "**" + t.Name + "**\n\n" + t.Description,
			}
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverAssociationPropertyValue(line string, handler FormatHandler, ctx HoverContext) *HoverResult {
	value := handler.ExtractValueFromLine(line)
	value = strings.Trim(value, "'\"")

	ap := ctx.Registry.GetAssociationProperty(value)
	if ap != nil {
		return &HoverResult{
			Contents: formatAssociationPropertyDoc(value, ap),
		}
	}
	return nil
}

func (p *ROSTemplateProvider) hoverIntrinsicFunction(line string) *HoverResult {
	trimmed := strings.TrimSpace(line)
	for _, fn := range ROSIntrinsicFunctions {
		if strings.Contains(trimmed, fn.Name) || strings.Contains(trimmed, fn.ShortTag) {
			return &HoverResult{
				Contents: "**" + fn.Name + "**\n\n" + fn.Usage + "\n\n```yaml\n" + fn.ParamFormat + "\n```",
			}
		}
	}
	return nil
}

// --- Validation implementations ---

func (p *ROSTemplateProvider) validateFormatVersion(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	var diags []protocol.Diagnostic
	msg := i18n.Msg()

	if !pt.HasROSTemplateFormatVersion() {
		diagMsg := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.MissingFormatVersion })
		if diagMsg == "" {
			diagMsg = msg.LSPDiag.MissingFormatVersion
		}
		diags = append(diags, protocol.Diagnostic{
			Range: protocol.Range{
				Start: protocol.Position{Line: 0, Character: 0},
				End:   protocol.Position{Line: 0, Character: 1},
			},
			Severity: protocol.DiagnosticSeverityError,
			Source:   "ros-lsp",
			Message:  diagMsg,
		})
		return diags
	}

	version := pt.GetROSTemplateFormatVersion()
	if version != "2015-09-01" {
		line := handler.FindKeyLine(ctx.Content, "ROSTemplateFormatVersion")
		if line < 0 {
			line = 0
		}
		tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.InvalidFormatVersion })
		if tmpl == "" {
			tmpl = "Invalid ROSTemplateFormatVersion: %q (expected \"2015-09-01\")"
		}
		diags = append(diags, protocol.Diagnostic{
			Range: protocol.Range{
				Start: protocol.Position{Line: line, Character: 0},
				End:   protocol.Position{Line: line, Character: len("ROSTemplateFormatVersion")},
			},
			Severity: protocol.DiagnosticSeverityError,
			Source:   "ros-lsp",
			Message:  fmt.Sprintf(tmpl, version),
		})
	}

	return diags
}

func (p *ROSTemplateProvider) validateTopLevelKeys(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	validKeys := make(map[string]bool)
	for _, block := range ROSTopLevelBlocks {
		validKeys[block.Name] = true
	}

	var diags []protocol.Diagnostic
	for _, key := range pt.TopLevelKeys {
		if !validKeys[key] {
			line := handler.FindKeyLine(ctx.Content, key)
			if line < 0 {
				line = 0
			}
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.UnknownTopLevelKey })
			if tmpl == "" {
				tmpl = "Unknown top-level key: %q"
			}
			diagMsg := fmt.Sprintf(tmpl, key)
			if suggestion := findClosestMatch(key, validKeys); suggestion != "" {
				suffix := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.DidYouMean })
				if suffix == "" {
					suffix = " (did you mean %q?)"
				}
				diagMsg += fmt.Sprintf(suffix, suggestion)
			}
			diags = append(diags, protocol.Diagnostic{
				Range: protocol.Range{
					Start: protocol.Position{Line: line, Character: 0},
					End:   protocol.Position{Line: line, Character: len(key)},
				},
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  diagMsg,
			})
		}
	}

	return diags
}

func (p *ROSTemplateProvider) validateParameters(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	params := pt.GetParameters()
	if params == nil {
		return nil
	}

	var diags []protocol.Diagnostic

	for paramName, paramVal := range params {
		param, ok := paramVal.(map[string]interface{})
		if !ok {
			continue
		}

		typeVal, hasType := param["Type"]
		if !hasType {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.ParamMissingType })
			if tmpl == "" {
				tmpl = "Parameter %q is missing required Type field"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindParameterRange(ctx.Content, paramName),
				Severity: protocol.DiagnosticSeverityError,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, paramName),
			})
			continue
		}

		if typeStr, ok := typeVal.(string); ok {
			if !ValidParameterTypeValues[typeStr] {
				tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.ParamInvalidType })
				if tmpl == "" {
					tmpl = "Parameter %q: invalid Type value %q"
				}
				diags = append(diags, protocol.Diagnostic{
					Range:    handler.FindParameterAttrValueRange(ctx.Content, paramName, "Type"),
					Severity: protocol.DiagnosticSeverityWarning,
					Source:   "ros-lsp",
					Message:  fmt.Sprintf(tmpl, paramName, typeStr),
				})
			}
		}

		for attrName, attrVal := range param {
			expectedType, known := ROSParameterPropertyTypes[attrName]
			if !known || expectedType == "" || expectedType == "any" {
				continue
			}
			if !IsParamAttrTypeValid(attrVal, expectedType) {
				tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.ParamAttrTypeMismatch })
				if tmpl == "" {
					tmpl = "Parameter %q property %q: expected type %s, got %s"
				}
				diags = append(diags, protocol.Diagnostic{
					Range:    handler.FindParameterAttrValueRange(ctx.Content, paramName, attrName),
					Severity: protocol.DiagnosticSeverityWarning,
					Source:   "ros-lsp",
					Message:  fmt.Sprintf(tmpl, paramName, attrName, expectedType, DescribeValueType(attrVal)),
				})
			}
		}
	}

	return diags
}

func (p *ROSTemplateProvider) validateLocals(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	locals := pt.GetLocals()
	if locals == nil {
		return nil
	}

	var diags []protocol.Diagnostic

	for localName, localVal := range locals {
		local, ok := localVal.(map[string]interface{})
		if !ok {
			continue
		}

		typeVal, hasType := local["Type"]
		_, hasValue := local["Value"]

		localType := "Macro"
		if hasType {
			if typeStr, ok := typeVal.(string); ok {
				localType = typeStr
			}
		}

		if (localType == "Macro" || localType == "Eval") && !hasValue {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.LocalMissingValue })
			if tmpl == "" {
				tmpl = "Local %q (type %s) is missing required Value field"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindLocalsRange(ctx.Content, localName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, localName, localType),
			})
		}

		if strings.HasPrefix(localType, "DATASOURCE::") {
			if _, hasProps := local["Properties"]; !hasProps {
				tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.LocalDatasourceMissingProperties })
				if tmpl == "" {
					tmpl = "Local %q (type %s) is missing Properties field"
				}
				diags = append(diags, protocol.Diagnostic{
					Range:    handler.FindLocalsRange(ctx.Content, localName),
					Severity: protocol.DiagnosticSeverityWarning,
					Source:   "ros-lsp",
					Message:  fmt.Sprintf(tmpl, localName, localType),
				})
			}
		}
	}

	return diags
}

func (p *ROSTemplateProvider) validateResources(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext) []protocol.Diagnostic {
	resources := pt.GetResources()
	if resources == nil {
		return nil
	}

	var diags []protocol.Diagnostic

	for resName, resVal := range resources {
		res, ok := resVal.(map[string]interface{})
		if !ok {
			continue
		}

		typeName, hasType := res["Type"].(string)
		if !hasType {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.MissingType })
			if tmpl == "" {
				tmpl = "Resource %q is missing required Type field"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindResourceRange(ctx.Content, resName),
				Severity: protocol.DiagnosticSeverityError,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, resName),
			})
			continue
		}

		if !ctx.Registry.HasResourceType(typeName) {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.UnknownResourceType })
			if tmpl == "" {
				tmpl = "Unknown resource type: %q"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindResourceTypeRange(ctx.Content, resName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, typeName),
			})
			continue
		}

		diags = append(diags, p.validateRequiredProperties(pt, handler, ctx, resName, typeName, res)...)
		diags = append(diags, p.validatePropertyTypes(pt, handler, ctx, resName, typeName, res)...)
	}

	return diags
}

func (p *ROSTemplateProvider) validateRequiredProperties(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext, resName, typeName string, res map[string]interface{}) []protocol.Diagnostic {
	required := ctx.Registry.RequiredProperties(typeName)
	if len(required) == 0 {
		return nil
	}

	props, _ := res["Properties"].(map[string]interface{})

	tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.MissingRequiredProperty })
	if tmpl == "" {
		tmpl = "Resource %q missing required property: %s"
	}

	var diags []protocol.Diagnostic
	for _, reqProp := range required {
		if props == nil {
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindResourceRange(ctx.Content, resName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, resName, reqProp),
			})
			continue
		}
		val, exists := props[reqProp]
		if !exists {
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindResourceRange(ctx.Content, resName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, resName, reqProp),
			})
		} else if IsIntrinsicFunctionValue(val) {
			continue
		}
	}

	return diags
}

func (p *ROSTemplateProvider) validatePropertyTypes(pt *ParsedTemplate, handler FormatHandler, ctx ValidationContext, resName, typeName string, res map[string]interface{}) []protocol.Diagnostic {
	props, _ := res["Properties"].(map[string]interface{})
	if props == nil {
		return nil
	}

	var diags []protocol.Diagnostic
	for propName, propVal := range props {
		if IsIntrinsicFunctionValue(propVal) {
			continue
		}

		schemaProp := ctx.Registry.GetProperty(typeName, propName)
		if schemaProp == nil {
			continue
		}

		if !isTypeCompatible(propVal, schemaProp.Type) {
			tmpl := i18n.Get(func(m *i18n.Messages) string { return m.LSPDiag.TypeMismatch })
			if tmpl == "" {
				tmpl = "Property %q of resource %q: expected type %s"
			}
			diags = append(diags, protocol.Diagnostic{
				Range:    handler.FindResourcePropertyValueRange(ctx.Content, resName, propName),
				Severity: protocol.DiagnosticSeverityWarning,
				Source:   "ros-lsp",
				Message:  fmt.Sprintf(tmpl, propName, resName, schemaProp.Type),
			})
		}
	}

	return diags
}

func isTypeCompatible(val interface{}, expectedType string) bool {
	switch strings.ToLower(expectedType) {
	case "string":
		_, ok := val.(string)
		return ok
	case "number", "integer":
		switch val.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			return true
		}
		return false
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "list":
		_, ok := val.([]interface{})
		return ok
	case "map", "json":
		_, ok := val.(map[string]interface{})
		return ok
	default:
		return true
	}
}

func findClosestMatch(input string, validKeys map[string]bool) string {
	inputLower := strings.ToLower(input)
	for key := range validKeys {
		if strings.ToLower(key) == inputLower {
			return key
		}
		if len(input) > 3 && len(key) > 3 {
			if strings.HasPrefix(strings.ToLower(key), inputLower[:3]) ||
				strings.HasPrefix(inputLower, strings.ToLower(key[:3])) {
				return key
			}
		}
	}
	return ""
}
