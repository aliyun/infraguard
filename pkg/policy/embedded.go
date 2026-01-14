// Package policy manages policy library download and discovery.
package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
)

// LoadWithFallback loads policies by merging embedded, user-local, and workspace-local policies.
// Policy loading priority (highest to lowest):
//  1. Workspace-local policies: .infraguard/policies/ (current working directory)
//  2. User-local policies: ~/.infraguard/policies/
//  3. Embedded policies: compiled into the binary
//
// Policies with the same ID from higher-priority sources override lower-priority ones.
func LoadWithFallback() (*Loader, error) {
	loader := &Loader{
		index: &models.PolicyIndex{
			Rules:    make(map[string]*models.Rule),
			Packs:    make(map[string]*models.Pack),
			RuleList: make([]*models.Rule, 0),
			PackList: make([]*models.Pack, 0),
		},
	}

	// First, load embedded policies as the base (lowest priority)
	if err := loader.LoadEmbedded(); err != nil {
		// Embedded policies failing is not fatal, log and continue
		// This allows the tool to work even if embedded policies have issues
	}

	// Build extra modules from embedded helpers for parsing rules that depend on them
	extraModules := buildExtraModulesFromLoader(loader)

	// Then, load user-local policies (will override embedded ones with same ID)
	userPolicyDir := DefaultPolicyDir()
	if dirExists(userPolicyDir) {
		mergePoliciesFromDir(loader, userPolicyDir, extraModules)
	}

	// Finally, load workspace-local policies (highest priority, will override user-local and embedded)
	workspacePolicyDir := WorkspacePolicyDir()
	if dirExists(workspacePolicyDir) {
		mergePoliciesFromDir(loader, workspacePolicyDir, extraModules)
	}

	// If no policies loaded at all, return error
	if len(loader.GetAllRules()) == 0 && len(loader.GetAllPacks()) == 0 {
		msg := i18n.Msg()
		return nil, fmt.Errorf("%s", msg.Errors.NoPoliciesFound)
	}

	return loader, nil
}

// mergePoliciesFromDir loads policies from a directory and merges them into the loader.
// Policies from this directory will override existing ones with the same ID.
// The extraModules parameter provides helper libraries (e.g., embedded helpers) for parsing rules.
func mergePoliciesFromDir(loader *Loader, policyDir string, extraModules []RegoModule) {
	dirLoader := &Loader{
		policyDir:    policyDir,
		extraModules: extraModules,
		index: &models.PolicyIndex{
			Rules:    make(map[string]*models.Rule),
			Packs:    make(map[string]*models.Pack),
			RuleList: make([]*models.Rule, 0),
			PackList: make([]*models.Pack, 0),
		},
	}
	if err := dirLoader.Load(); err == nil {
		// Merge policies into main loader (higher priority overrides)
		for _, rule := range dirLoader.GetAllRules() {
			loader.index.Rules[rule.ID] = rule
			// Update RuleList: remove existing rule with same ID and add new one
			loader.index.RuleList = replaceOrAppendRule(loader.index.RuleList, rule)
		}
		for _, pack := range dirLoader.GetAllPacks() {
			loader.index.Packs[pack.ID] = pack
			// Update PackList: remove existing pack with same ID and add new one
			loader.index.PackList = replaceOrAppendPack(loader.index.PackList, pack)
		}
	}
}

// buildExtraModulesFromLoader builds a slice of RegoModules from the loader's LibModules.
// This allows user/workspace policies to use embedded helper libraries.
func buildExtraModulesFromLoader(loader *Loader) []RegoModule {
	var modules []RegoModule
	for path, content := range loader.GetLibModules() {
		modules = append(modules, RegoModule{Path: path, Content: content})
	}
	return modules
}

// replaceOrAppendRule replaces a rule with the same ID or appends it.
func replaceOrAppendRule(list []*models.Rule, rule *models.Rule) []*models.Rule {
	for i, r := range list {
		if r.ID == rule.ID {
			list[i] = rule
			return list
		}
	}
	return append(list, rule)
}

// replaceOrAppendPack replaces a pack with the same ID or appends it.
func replaceOrAppendPack(list []*models.Pack, pack *models.Pack) []*models.Pack {
	for i, p := range list {
		if p.ID == pack.ID {
			list[i] = pack
			return list
		}
	}
	return append(list, pack)
}

// LoadEmbedded loads policies from the embedded filesystem.
// Supports provider-first directory structure: {provider}/rules/, {provider}/packs/, {provider}/lib/
func (l *Loader) LoadEmbedded() error {
	// Use pre-computed index if available to save runtime parsing overhead
	if EmbeddedIndex != nil {
		for _, rule := range EmbeddedIndex.RuleList {
			l.index.AddRule(rule)
		}
		for _, pack := range EmbeddedIndex.PackList {
			l.index.AddPack(pack)
		}
		if l.index.LibModules == nil {
			l.index.LibModules = make(map[string]string)
		}
		for k, v := range EmbeddedIndex.LibModules {
			l.index.LibModules[k] = v
		}
		return nil
	}

	// Read root directory to find provider directories
	// Since we are removing raw embedded FS support, we only support pre-computed index.
	// If EmbeddedIndex is nil (e.g. not generated), we simply return nil as there are no embedded policies.
	return nil
}

// GenerateIDPrefix generates the ID prefix from the file path relative to the base directory.
// Supports provider-first structure: "policies/aliyun/rules/ecs_public_ip.rego" with base "policies/aliyun/rules" -> "rule:aliyun"
// For embedded FS paths: "aliyun/rules/ecs_public_ip.rego" with base "aliyun/rules" -> "rule:aliyun"
func GenerateIDPrefix(filePath, baseDir, idType string) string {
	// Get relative path from base directory
	relPath, err := filepath.Rel(baseDir, filePath)
	if err != nil {
		return idType + ":"
	}

	// Get directory part (without filename)
	dir := filepath.Dir(relPath)
	if dir == "." {
		// File is directly in baseDir, extract provider from baseDir
		// baseDir format: {provider}/rules or {provider}/packs
		parts := strings.Split(baseDir, string(filepath.Separator))
		if len(parts) >= 1 {
			provider := parts[0]
			return idType + ":" + provider + ":"
		}
		return idType + ":"
	}

	// Convert directory separators to colons
	parts := strings.Split(dir, string(filepath.Separator))
	if len(parts) == 0 {
		return idType + ":"
	}

	// Extract provider from baseDir: {provider}/rules or {provider}/packs
	baseParts := strings.Split(baseDir, string(filepath.Separator))
	var provider string
	// Find "rules" or "packs" directory and the element before it is the provider
	for i := len(baseParts) - 1; i > 0; i-- {
		if baseParts[i] == "rules" || baseParts[i] == "packs" {
			provider = baseParts[i-1]
			break
		}
	}
	// Fallback for cases where baseDir is just {provider}
	if provider == "" && len(baseParts) >= 1 {
		provider = baseParts[len(baseParts)-1]
		if provider == "rules" || provider == "packs" {
			if len(baseParts) >= 2 {
				provider = baseParts[len(baseParts)-2]
			}
		}
	}
	// If provider is still "policies", it's not the actual provider
	if provider == "policies" && len(parts) > 0 {
		provider = parts[0]
	}

	// Filter out empty parts and join with colons
	var validParts []string
	if provider != "" {
		validParts = append(validParts, provider)
	}
	for _, part := range parts {
		if part != "" && part != "." && part != "rules" && part != "packs" {
			validParts = append(validParts, part)
		}
	}

	if len(validParts) == 0 {
		return idType + ":"
	}

	return idType + ":" + strings.Join(validParts, ":") + ":"
}

// GenerateRuleID generates a full rule ID from the file path and rule name.
// e.g., "policies/aliyun/rules/ecs_public_ip.rego" with name "ecs-public-ip" -> "rule:aliyun:ecs-public-ip"
func GenerateRuleID(filePath, baseDir, ruleName string) string {
	prefix := GenerateIDPrefix(filePath, baseDir, "rule")
	return prefix + ruleName
}

// GeneratePackID generates a full pack ID from the file path and pack name.
// e.g., "policies/aliyun/packs/security_baseline.rego" with name "security-baseline" -> "pack:aliyun:security-baseline"
func GeneratePackID(filePath, baseDir, packName string) string {
	prefix := GenerateIDPrefix(filePath, baseDir, "pack")
	return prefix + packName
}
