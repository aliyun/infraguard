package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
)

type RuleMeta struct {
	ID             string            `json:"id"`
	Name           map[string]string `json:"name"`
	Severity       string            `json:"severity"`
	Description    map[string]string `json:"description"`
	Reason         map[string]string `json:"reason"`
	Recommendation map[string]string `json:"recommendation"`
	ResourceTypes  []string          `json:"resource_types"`
}

type PackMeta struct {
	ID          string            `json:"id"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description"`
	Rules       []string          `json:"rules"`
	Path        string            `json:"-"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	docsDir := filepath.Join(projectRoot, "docs", "docs")

	// Generate rule documentation and collect rules for validation
	// Traverse provider-first structure: policies/{provider}/rules/
	policiesDir := filepath.Join(projectRoot, "policies")
	providerRules, err := generateRulesDocs(policiesDir, docsDir)
	if err != nil {
		return fmt.Errorf("failed to generate rules docs: %w", err)
	}

	// Generate pack documentation with validation
	// Traverse provider-first structure: policies/{provider}/packs/
	if err := generatePacksDocs(policiesDir, docsDir, providerRules); err != nil {
		return fmt.Errorf("failed to generate packs docs: %w", err)
	}

	fmt.Println("✅ Policy documentation generated successfully")
	return nil
}

func generateRulesDocs(policiesDir, docsDir string) (map[string]map[string]bool, error) {
	// Read provider directories from policies root
	providers, err := os.ReadDir(policiesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policies directory: %w", err)
	}

	providerRules := make(map[string]map[string]bool)

	for _, provider := range providers {
		if !provider.IsDir() {
			continue
		}

		providerName := provider.Name()
		// Skip non-provider directories
		if providerName == "testdata" || providerName == "embed.go" {
			continue
		}

		// Check for provider-first structure: {provider}/rules/
		providerRulesDir := filepath.Join(policiesDir, providerName, "rules")
		if _, err := os.Stat(providerRulesDir); os.IsNotExist(err) {
			continue // Skip if rules directory doesn't exist
		}

		providerDocsDir := filepath.Join(docsDir, "policies", providerName, "rules")

		if err := os.MkdirAll(providerDocsDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create docs directory: %w", err)
		}

		rules, err := loadRules(providerRulesDir, filepath.Join(policiesDir, providerName))
		if err != nil {
			return nil, fmt.Errorf("failed to load rules for %s: %w", providerName, err)
		}

		providerRules[providerName] = make(map[string]bool)
		for _, rule := range rules {
			// Store stripped ID for validation
			ruleID := rule.ID
			if strings.HasPrefix(ruleID, "rule:"+providerName+":") {
				ruleID = strings.TrimPrefix(ruleID, "rule:"+providerName+":")
			}
			providerRules[providerName][ruleID] = true

			if err := generateRulePage(rule, providerDocsDir, providerName); err != nil {
				return nil, fmt.Errorf("failed to generate rule page for %s: %w", rule.ID, err)
			}
		}

		if err := generateRulesIndexPage(rules, docsDir, providerName); err != nil {
			return nil, fmt.Errorf("failed to generate rules index for %s: %w", providerName, err)
		}

		fmt.Printf("✓ Generated %d rule docs for %s\n", len(rules), providerName)
	}

	return providerRules, nil
}

func generatePacksDocs(policiesDir, docsDir string, providerRules map[string]map[string]bool) error {
	// Read provider directories from policies root
	providers, err := os.ReadDir(policiesDir)
	if err != nil {
		return fmt.Errorf("failed to read policies directory: %w", err)
	}

	for _, provider := range providers {
		if !provider.IsDir() {
			continue
		}

		providerName := provider.Name()
		// Skip non-provider directories
		if providerName == "testdata" || providerName == "embed.go" {
			continue
		}

		// Check for provider-first structure: {provider}/packs/
		providerPacksDir := filepath.Join(policiesDir, providerName, "packs")
		if _, err := os.Stat(providerPacksDir); os.IsNotExist(err) {
			continue // Skip if packs directory doesn't exist
		}

		providerDocsDir := filepath.Join(docsDir, "policies", providerName, "packs")

		if err := os.MkdirAll(providerDocsDir, 0755); err != nil {
			return fmt.Errorf("failed to create docs directory: %w", err)
		}

		packs, err := loadPacks(providerPacksDir)
		if err != nil {
			return fmt.Errorf("failed to load packs for %s: %w", providerName, err)
		}

		for _, pack := range packs {
			// Validate that all rules in the pack exist
			var validRules []string
			for _, ruleID := range pack.Rules {
				// Strip prefix if present for validation
				strippedID := ruleID
				if strings.HasPrefix(ruleID, "rule:"+providerName+":") {
					strippedID = strings.TrimPrefix(ruleID, "rule:"+providerName+":")
				}

				if !providerRules[providerName][strippedID] {
					fmt.Printf("⚠️  Rule %s in pack %s (provider %s) does not exist. Commenting it out...\n", ruleID, pack.ID, providerName)
					if err := commentOutRuleInPack(pack.Path, ruleID); err != nil {
						fmt.Printf("❌ Failed to comment out rule %s in %s: %v\n", ruleID, pack.Path, err)
					}
					continue
				}
				validRules = append(validRules, ruleID)
			}
			pack.Rules = validRules

			if err := generatePackPage(pack, providerDocsDir, providerName); err != nil {
				return fmt.Errorf("failed to generate pack page for %s: %w", pack.ID, err)
			}
		}

		if err := generatePacksIndexPage(packs, docsDir, providerName); err != nil {
			return fmt.Errorf("failed to generate packs index for %s: %w", providerName, err)
		}

		fmt.Printf("✓ Generated %d pack docs for %s\n", len(packs), providerName)
	}

	return nil
}

func loadRules(rulesDir, providerDir string) ([]RuleMeta, error) {
	// Load rules directory
	result, err := loader.NewFileLoader().AsBundle(rulesDir)
	if err != nil {
		return nil, err
	}

	// Also load helper library from {provider}/lib/
	helperDir := filepath.Join(providerDir, "lib")
	helperResult, err := loader.NewFileLoader().AsBundle(helperDir)
	if err == nil {
		// Merge helper modules if available
		for _, moduleFile := range helperResult.Modules {
			result.Modules = append(result.Modules, moduleFile)
		}
	}

	modules := make(map[string]*ast.Module)
	for _, moduleFile := range result.Modules {
		module, err := ast.ParseModule(moduleFile.Path, string(moduleFile.Raw))
		if err != nil {
			continue
		}
		modules[moduleFile.Path] = module
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		// Ignore compilation errors, just skip problematic files
		// return nil, compiler.Errors
	}

	var rules []RuleMeta
	for _, module := range modules {
		// Only extract from rule modules
		if !strings.Contains(module.Package.Path.String(), ".rules.") {
			continue
		}
		rule, err := extractRuleMeta(module, compiler)
		if err != nil {
			continue
		}
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	return rules, nil
}

func loadPacks(dir string) ([]PackMeta, error) {
	result, err := loader.NewFileLoader().AsBundle(dir)
	if err != nil {
		return nil, err
	}

	modules := make(map[string]*ast.Module)
	for _, moduleFile := range result.Modules {
		module, err := ast.ParseModule(moduleFile.Path, string(moduleFile.Raw))
		if err != nil {
			continue
		}
		modules[moduleFile.Path] = module
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		// Ignore compilation errors
	}

	var packs []PackMeta
	for path, module := range modules {
		pack, err := extractPackMeta(module, compiler)
		if err != nil {
			continue
		}
		pack.Path = path
		packs = append(packs, pack)
	}

	sort.Slice(packs, func(i, j int) bool {
		return packs[i].ID < packs[j].ID
	})

	return packs, nil
}

func extractRuleMeta(module *ast.Module, compiler *ast.Compiler) (RuleMeta, error) {
	var meta RuleMeta

	// Find the rule_meta rule in the module
	for _, rule := range module.Rules {
		if rule.Head.Name.String() == "rule_meta" {
			// Evaluate the rule to get its value
			term := rule.Head.Value
			if term == nil {
				continue
			}

			// Parse the object
			obj, ok := term.Value.(ast.Object)
			if !ok {
				continue
			}

			// Extract fields
			meta.ID = extractString(obj, "id")
			meta.Name = extractI18nMap(obj, "name")
			meta.Severity = extractString(obj, "severity")
			meta.Description = extractI18nMap(obj, "description")
			meta.Reason = extractI18nMap(obj, "reason")
			meta.Recommendation = extractI18nMap(obj, "recommendation")
			meta.ResourceTypes = extractStringArray(obj, "resource_types")

			if meta.ID != "" {
				return meta, nil
			}
		}
	}

	return meta, fmt.Errorf("rule_meta not found.")
}

func extractPackMeta(module *ast.Module, compiler *ast.Compiler) (PackMeta, error) {
	var meta PackMeta

	for _, rule := range module.Rules {
		if rule.Head.Name.String() == "pack_meta" {
			term := rule.Head.Value
			if term == nil {
				continue
			}

			obj, ok := term.Value.(ast.Object)
			if !ok {
				continue
			}

			meta.ID = extractString(obj, "id")
			meta.Name = extractI18nMap(obj, "name")
			meta.Description = extractI18nMap(obj, "description")
			meta.Rules = extractStringArray(obj, "rules")

			if meta.ID != "" {
				return meta, nil
			}
		}
	}

	return meta, fmt.Errorf("pack_meta not found.")
}

func extractString(obj ast.Object, key string) string {
	keyTerm := ast.StringTerm(key)
	value := obj.Get(keyTerm)
	if value == nil {
		return ""
	}

	if str, ok := value.Value.(ast.String); ok {
		return string(str)
	}

	return ""
}

func extractI18nMap(obj ast.Object, key string) map[string]string {
	result := make(map[string]string)
	keyTerm := ast.StringTerm(key)
	value := obj.Get(keyTerm)
	if value == nil {
		return result
	}

	// Check if it's a string (non-i18n)
	if str, ok := value.Value.(ast.String); ok {
		s := string(str)
		result["en"] = s
		result["zh"] = s
		return result
	}

	// Check if it's an object (i18n map)
	if mapObj, ok := value.Value.(ast.Object); ok {
		enValue := mapObj.Get(ast.StringTerm("en"))
		if enValue != nil {
			if str, ok := enValue.Value.(ast.String); ok {
				result["en"] = string(str)
			}
		}

		zhValue := mapObj.Get(ast.StringTerm("zh"))
		if zhValue != nil {
			if str, ok := zhValue.Value.(ast.String); ok {
				result["zh"] = string(str)
			}
		}
	}

	return result
}

func extractStringArray(obj ast.Object, key string) []string {
	var result []string
	keyTerm := ast.StringTerm(key)
	value := obj.Get(keyTerm)
	if value == nil {
		return result
	}

	// Use type switch to handle Array properly
	switch v := value.Value.(type) {
	case *ast.Array:
		v.Foreach(func(term *ast.Term) {
			if str, ok := term.Value.(ast.String); ok {
				result = append(result, string(str))
			}
		})
	}

	return result
}

func generateRulePage(rule RuleMeta, outputDir, provider string) error {
	// Generate English version
	// Strip provider prefix from ID for filename if present (e.g., rule:aliyun:rule-id -> rule-id)
	ruleFilename := rule.ID
	if strings.HasPrefix(rule.ID, "rule:"+provider+":") {
		ruleFilename = strings.TrimPrefix(rule.ID, "rule:"+provider+":")
	}

	filenameEn := filepath.Join(outputDir, ruleFilename+".md")
	nameEn := getI18nString(rule.Name, "en")
	descEn := getI18nString(rule.Description, "en")
	reasonEn := getI18nString(rule.Reason, "en")
	recEn := getI18nString(rule.Recommendation, "en")

	contentEn := fmt.Sprintf(`---
title: %s
sidebar_label: %s
---

# %s

**ID**: `+"`rule:%s:%s`"+`  
**Severity**: `+"`%s`"+`

## Description

%s

## Reason for Violation

%s

## Recommendation

%s

## Resource Types

This rule applies to the following resource types:

%s

`,
		nameEn,
		nameEn,
		nameEn,
		provider, ruleFilename, // Use ruleFilename for ID in documentation if needed, or keep rule.ID?
		// Actually rule.ID is rule:aliyun:xxx, let's see how it's used in the template.
		// Original: provider, rule.ID.
		// If rule.ID is rule:aliyun:xxx, then it becomes rule:aliyun:rule:aliyun:xxx. That's wrong.
		// Let's use the stripped ID.
		rule.Severity,
		descEn,
		reasonEn,
		recEn,
		formatResourceTypes(rule.ResourceTypes),
	)

	if err := os.WriteFile(filenameEn, []byte(contentEn), 0644); err != nil {
		return err
	}

	// Generate Chinese version
	zhDir := strings.Replace(outputDir, "/docs/docs/", "/docs/i18n/zh/docusaurus-plugin-content-docs/current/", 1)
	if err := os.MkdirAll(zhDir, 0755); err != nil {
		return err
	}

	filenameZh := filepath.Join(zhDir, ruleFilename+".md")
	nameZh := getI18nString(rule.Name, "zh")
	descZh := getI18nString(rule.Description, "zh")
	reasonZh := getI18nString(rule.Reason, "zh")
	recZh := getI18nString(rule.Recommendation, "zh")

	contentZh := fmt.Sprintf(`---
title: %s
sidebar_label: %s
---

# %s

**ID**: `+"`rule:%s:%s`"+`  
**严重程度**: `+"`%s`"+`

## 描述

%s

## 违规原因

%s

## 建议

%s

## 资源类型

此规则适用于以下资源类型：

%s

---

_此文档由策略元数据自动生成。_
`,
		nameZh,
		nameZh,
		nameZh,
		provider, ruleFilename,
		rule.Severity,
		descZh,
		reasonZh,
		recZh,
		formatResourceTypes(rule.ResourceTypes),
	)

	return os.WriteFile(filenameZh, []byte(contentZh), 0644)
}

func generatePackPage(pack PackMeta, outputDir, provider string) error {
	// Generate English version
	filenameEn := filepath.Join(outputDir, pack.ID+".md")
	nameEn := getI18nString(pack.Name, "en")
	descEn := getI18nString(pack.Description, "en")

	contentEn := fmt.Sprintf(`---
title: %s
sidebar_label: %s
---

# %s

**ID**: `+"`pack:%s:%s`"+`

## Description

%s

## Included Rules

This compliance pack includes the following rules:

%s

`,
		nameEn,
		nameEn,
		nameEn,
		provider, pack.ID,
		descEn,
		formatRulesList(pack.Rules, provider),
	)

	if err := os.WriteFile(filenameEn, []byte(contentEn), 0644); err != nil {
		return err
	}

	// Generate Chinese version
	zhDir := strings.Replace(outputDir, "/docs/docs/", "/docs/i18n/zh/docusaurus-plugin-content-docs/current/", 1)
	if err := os.MkdirAll(zhDir, 0755); err != nil {
		return err
	}

	filenameZh := filepath.Join(zhDir, pack.ID+".md")
	nameZh := getI18nString(pack.Name, "zh")
	descZh := getI18nString(pack.Description, "zh")

	contentZh := fmt.Sprintf(`---
title: %s
sidebar_label: %s
---

# %s

**ID**: `+"`pack:%s:%s`"+`

## 描述

%s

## 包含的规则

此合规包包含以下规则：

%s

---

_此文档由策略元数据自动生成。_
`,
		nameZh,
		nameZh,
		nameZh,
		provider, pack.ID,
		descZh,
		formatRulesListZh(pack.Rules, provider),
	)

	return os.WriteFile(filenameZh, []byte(contentZh), 0644)
}

func generateRulesIndexPage(rules []RuleMeta, docsDir, provider string) error {
	// Generate English version
	filenameEn := filepath.Join(docsDir, "policies", provider, "rules.md")

	contentEn := fmt.Sprintf(`---
title: %s Rules
sidebar_label: Rules
---

# %s Rules

Total rules: **%d**

## Rules by Severity

`, strings.Title(provider), strings.Title(provider), len(rules))

	bySeverity := map[string][]RuleMeta{
		"high":   {},
		"medium": {},
		"low":    {},
	}
	for _, rule := range rules {
		bySeverity[rule.Severity] = append(bySeverity[rule.Severity], rule)
	}

	for _, severity := range []string{"high", "medium", "low"} {
		severityRules := bySeverity[severity]
		if len(severityRules) == 0 {
			continue
		}

		contentEn += fmt.Sprintf("### %s Severity (%d rules)\n\n", strings.Title(severity), len(severityRules))
		contentEn += "| Rule ID | Name | Description |\n"
		contentEn += "|---------|------|-------------|\n"

		for _, rule := range severityRules {
			nameEn := getI18nString(rule.Name, "en")
			descEn := getI18nString(rule.Description, "en")

			ruleFilename := rule.ID
			if strings.HasPrefix(rule.ID, "rule:"+provider+":") {
				ruleFilename = strings.TrimPrefix(rule.ID, "rule:"+provider+":")
			}

			contentEn += fmt.Sprintf("| [%s](./rules/%s) | %s | %s |\n",
				ruleFilename, ruleFilename, nameEn, descEn)
		}
		contentEn += "\n"
	}

	if err := os.WriteFile(filenameEn, []byte(contentEn), 0644); err != nil {
		return err
	}

	// Generate Chinese version
	zhDir := filepath.Join(docsDir, "../i18n/zh/docusaurus-plugin-content-docs/current/policies", provider)
	if err := os.MkdirAll(zhDir, 0755); err != nil {
		return err
	}

	filenameZh := filepath.Join(zhDir, "rules.md")

	contentZh := fmt.Sprintf(`---
title: %s 规则
sidebar_label: 规则
---

# %s 规则

规则总数：**%d**

## 按严重程度分类

`, strings.Title(provider), strings.Title(provider), len(rules))

	for _, severity := range []string{"high", "medium", "low"} {
		severityRules := bySeverity[severity]
		if len(severityRules) == 0 {
			continue
		}

		severityZh := map[string]string{"high": "高", "medium": "中", "low": "低"}[severity]
		contentZh += fmt.Sprintf("### %s严重程度（%d 条规则）\n\n", severityZh, len(severityRules))
		contentZh += "| 规则 ID | 名称 | 描述 |\n"
		contentZh += "|---------|------|------|\n"

		for _, rule := range severityRules {
			nameZh := getI18nString(rule.Name, "zh")
			descZh := getI18nString(rule.Description, "zh")

			ruleFilename := rule.ID
			if strings.HasPrefix(rule.ID, "rule:"+provider+":") {
				ruleFilename = strings.TrimPrefix(rule.ID, "rule:"+provider+":")
			}

			contentZh += fmt.Sprintf("| [%s](./rules/%s) | %s | %s |\n",
				ruleFilename, ruleFilename, nameZh, descZh)
		}
		contentZh += "\n"
	}

	contentZh += "\n---\n\n_此文档由策略元数据自动生成。_\n"

	return os.WriteFile(filenameZh, []byte(contentZh), 0644)
}

func generatePacksIndexPage(packs []PackMeta, docsDir, provider string) error {
	// Generate English version
	filenameEn := filepath.Join(docsDir, "policies", provider, "packs.md")

	contentEn := fmt.Sprintf(`---
title: %s Compliance Packs
sidebar_label: Packs
---

# %s Compliance Packs

Total packs: **%d**

## Available Packs

| Pack ID | Name | Rules | Description |
|---------|------|-------|-------------|
`, strings.Title(provider), strings.Title(provider), len(packs))

	for _, pack := range packs {
		nameEn := getI18nString(pack.Name, "en")
		descEn := getI18nString(pack.Description, "en")
		contentEn += fmt.Sprintf("| [%s](./packs/%s) | %s | %d | %s |\n",
			pack.ID, pack.ID, nameEn, len(pack.Rules), descEn)
	}

	if err := os.WriteFile(filenameEn, []byte(contentEn), 0644); err != nil {
		return err
	}

	// Generate Chinese version
	zhDir := filepath.Join(docsDir, "../i18n/zh/docusaurus-plugin-content-docs/current/policies", provider)
	if err := os.MkdirAll(zhDir, 0755); err != nil {
		return err
	}

	filenameZh := filepath.Join(zhDir, "packs.md")

	contentZh := fmt.Sprintf(`---
title: %s 合规包
sidebar_label: 合规包
---

# %s 合规包

合规包总数：**%d**

## 可用的合规包

| 合规包 ID | 名称 | 规则数 | 描述 |
|---------|------|--------|------|
`, strings.Title(provider), strings.Title(provider), len(packs))

	for _, pack := range packs {
		nameZh := getI18nString(pack.Name, "zh")
		descZh := getI18nString(pack.Description, "zh")
		contentZh += fmt.Sprintf("| [%s](./packs/%s) | %s | %d | %s |\n",
			pack.ID, pack.ID, nameZh, len(pack.Rules), descZh)
	}

	contentZh += "\n---\n\n_此文档由策略元数据自动生成。_\n"

	return os.WriteFile(filenameZh, []byte(contentZh), 0644)
}

func getI18nString(m map[string]string, lang string) string {
	if v, ok := m[lang]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return ""
}

func formatResourceTypes(types []string) string {
	if len(types) == 0 {
		return "_No specific resource types_"
	}
	var result strings.Builder
	for _, t := range types {
		result.WriteString(fmt.Sprintf("- `%s`\n", t))
	}
	return result.String()
}

func formatRulesList(rules []string, provider string) string {
	var result strings.Builder
	for _, ruleID := range rules {
		ruleFilename := ruleID
		if strings.HasPrefix(ruleID, "rule:"+provider+":") {
			ruleFilename = strings.TrimPrefix(ruleID, "rule:"+provider+":")
		}
		result.WriteString(fmt.Sprintf("- [`rule:%s:%s`](../rules/%s)\n", provider, ruleFilename, ruleFilename))
	}
	return result.String()
}

func formatRulesListZh(rules []string, provider string) string {
	var result strings.Builder
	for _, ruleID := range rules {
		ruleFilename := ruleID
		if strings.HasPrefix(ruleID, "rule:"+provider+":") {
			ruleFilename = strings.TrimPrefix(ruleID, "rule:"+provider+":")
		}
		result.WriteString(fmt.Sprintf("- [`rule:%s:%s`](../rules/%s)\n", provider, ruleFilename, ruleFilename))
	}
	return result.String()
}

func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

func commentOutRuleInPack(path, ruleID string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Regex to find the rule ID in a string within an array, possibly followed by a comma
	// Matches: "rule-id" or "rule-id",
	re := regexp.MustCompile(`(?m)^(\s*)("` + ruleID + `",?)(\s*)$`)

	newContent := re.ReplaceAllString(string(content), `$1# $2$3`)

	if string(content) == newContent {
		// Try a less strict version if the above fails (e.g., if it's not the only thing on the line)
		re2 := regexp.MustCompile(`"` + ruleID + `"`)
		newContent = re2.ReplaceAllString(string(content), `# "`+ruleID+`"`)
		if string(content) == newContent {
			return fmt.Errorf("rule ID %s not found in %s.", ruleID, path)
		}
	}

	return os.WriteFile(path, []byte(newContent), 0644)
}
