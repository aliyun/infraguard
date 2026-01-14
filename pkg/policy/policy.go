// Package policy manages policy library download and discovery.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/hashicorp/go-getter"
)

// DefaultRepo is the default policy repository.
const DefaultRepo = "github.com/aliyun/infraguard"

// DefaultPolicyDir returns the default user-level policy storage directory (~/.infraguard/policies).
func DefaultPolicyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".infraguard/policies"
	}
	// Allow override via environment variable for testing
	if dir := os.Getenv("INFRAGUARD_POLICY_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(home, ".infraguard", "policies")
}

// WorkspacePolicyDir returns the workspace-local policy directory (.infraguard/policies)
// relative to the current working directory.
func WorkspacePolicyDir() string {
	// Allow override via environment variable for testing
	if dir := os.Getenv("INFRAGUARD_WORKSPACE_POLICY_DIR"); dir != "" {
		return dir
	}
	cwd, err := os.Getwd()
	if err != nil {
		return ".infraguard/policies"
	}
	return filepath.Join(cwd, ".infraguard", "policies")
}

// Loader handles policy loading with priority and indexing.
type Loader struct {
	policyDir    string
	index        *models.PolicyIndex
	extraModules []RegoModule // Extra helper modules for parsing rules
}

// Load discovers and loads all rules and packs from the policy directory.
// Supports two directory structures:
//  1. Provider-first: {provider}/rules/, {provider}/packs/, {provider}/lib/
//  2. Flat: {name}/*.rego (rules directly in subdirectory)
func (l *Loader) Load() error {
	// Iterate through subdirectories
	msg := i18n.Msg()
	entries, err := os.ReadDir(l.policyDir)
	if err != nil {
		return fmt.Errorf(msg.Errors.ReadPolicyDirectory, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		subDir := entry.Name()
		subDirPath := filepath.Join(l.policyDir, subDir)

		// Check if it's provider-first structure: {provider}/rules/ or {provider}/packs/
		rulesDir := filepath.Join(subDirPath, "rules")
		packsDir := filepath.Join(subDirPath, "packs")
		hasRulesDir := dirExists(rulesDir)
		hasPacksDir := dirExists(packsDir)

		if hasRulesDir || hasPacksDir {
			// Provider-first structure: load from {provider}/rules/ and {provider}/packs/
			if hasRulesDir {
				rules, err := DiscoverRulesWithExtraModules(rulesDir, l.extraModules)
				if err != nil {
					return fmt.Errorf(msg.Errors.DiscoverRulesForProvider, subDir, err)
				}
				for _, rule := range rules {
					l.index.AddRule(rule)
				}
			}

			if hasPacksDir {
				packs, err := DiscoverPacks(packsDir)
				if err != nil {
					return fmt.Errorf(msg.Errors.DiscoverPacksForProvider, subDir, err)
				}
				for _, pack := range packs {
					l.index.AddPack(pack)
				}
			}
		} else {
			// Flat structure: load .rego files directly from subdirectory
			// Check if directory contains .rego files
			if hasRegoFiles(subDirPath) {
				rules, err := DiscoverRulesWithExtraModules(subDirPath, l.extraModules)
				if err != nil {
					return fmt.Errorf(msg.Errors.DiscoverRulesForProvider, subDir, err)
				}
				for _, rule := range rules {
					l.index.AddRule(rule)
				}

				// Also try to discover packs in the same directory
				packs, err := DiscoverPacks(subDirPath)
				if err != nil {
					return fmt.Errorf(msg.Errors.DiscoverPacksForProvider, subDir, err)
				}
				for _, pack := range packs {
					l.index.AddPack(pack)
				}
			}
		}
	}

	return nil
}

// hasRegoFiles checks if a directory contains any .rego files.
func hasRegoFiles(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".rego") {
			return true
		}
	}
	return false
}

// GetIndex returns the loaded policy index.
func (l *Loader) GetIndex() *models.PolicyIndex {
	return l.index
}

// GetRule returns a rule by ID.
func (l *Loader) GetRule(id string) *models.Rule {
	return l.index.GetRule(id)
}

// GetPack returns a pack by ID.
func (l *Loader) GetPack(id string) *models.Pack {
	return l.index.GetPack(id)
}

// GetRulesForPack returns all rules for a given pack ID.
func (l *Loader) GetRulesForPack(packID string) []*models.Rule {
	return l.index.GetRulesForPack(packID)
}

// GetAllRules returns all loaded rules.
func (l *Loader) GetAllRules() []*models.Rule {
	return l.index.RuleList
}

// GetAllPacks returns all loaded packs.
func (l *Loader) GetAllPacks() []*models.Pack {
	return l.index.PackList
}

// GetLibModules returns all loaded library modules.
func (l *Loader) GetLibModules() map[string]string {
	if l.index.LibModules == nil {
		return make(map[string]string)
	}
	return l.index.LibModules
}

// MatchRules returns all rules matching the given pattern.
// The pattern supports `*` wildcard matching.
// Returns empty slice if no rules match.
func (l *Loader) MatchRules(pattern string) []*models.Rule {
	var matches []*models.Rule
	for _, rule := range l.index.RuleList {
		if MatchPattern(pattern, rule.ID) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// MatchPacks returns all packs matching the given pattern.
// The pattern supports `*` wildcard matching.
// Returns empty slice if no packs match.
func (l *Loader) MatchPacks(pattern string) []*models.Pack {
	var matches []*models.Pack
	for _, pack := range l.index.PackList {
		if MatchPattern(pattern, pack.ID) {
			matches = append(matches, pack)
		}
	}
	return matches
}

// dirExists checks if a directory exists.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// Manager handles policy library operations.
type Manager struct {
	policyDir string
}

// NewManager creates a new policy manager.
func NewManager(policyDir string) *Manager {
	return &Manager{policyDir: policyDir}
}

// Update downloads and updates the policy library from a repository.
// It uses "single-version overwrite" strategy: clears existing policies before download.
func (m *Manager) Update(repo, version string) error {
	msg := i18n.Msg()
	// Clean existing policies (single-version overwrite)
	if err := os.RemoveAll(m.policyDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf(msg.Errors.CleanPolicyDirectory, err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(m.policyDir, 0755); err != nil {
		return fmt.Errorf(msg.Errors.CreatePolicyDirectory, err)
	}

	// Build go-getter URL
	getterURL := buildGetterURL(repo, version)

	// Download using go-getter
	client := &getter.Client{
		Src:  getterURL,
		Dst:  m.policyDir,
		Mode: getter.ClientModeDir,
	}

	if err := client.Get(); err != nil {
		return fmt.Errorf(msg.Errors.DownloadPolicies, err)
	}

	return nil
}

// buildGetterURL constructs a go-getter compatible URL from various repo formats.
// Supported formats:
// - host/path (e.g., github.com/aliyun/infraguard)
// - HTTPS URL (e.g., https://github.com/aliyun/infraguard.git)
// - SSH URL (e.g., ssh://git@github.com/aliyun/infraguard.git)
// - SCP-like (e.g., git@github.com:aliyun/infraguard.git)
func buildGetterURL(repo, version string) string {
	repo = strings.TrimSpace(repo)

	// Pattern for SCP-like format: git@host:org/repo.git
	scpPattern := regexp.MustCompile(`^git@([^:]+):(.+?)(?:\.git)?$`)

	var baseURL string

	switch {
	case strings.HasPrefix(repo, "https://"):
		// HTTPS URL
		baseURL = strings.TrimSuffix(repo, ".git")
	case strings.HasPrefix(repo, "ssh://"):
		// SSH URL - keep as is
		baseURL = strings.TrimSuffix(repo, ".git")
	case scpPattern.MatchString(repo):
		// SCP-like format: git@host:org/repo.git -> ssh://git@host/org/repo
		matches := scpPattern.FindStringSubmatch(repo)
		host := matches[1]
		path := strings.TrimSuffix(matches[2], ".git")
		baseURL = fmt.Sprintf("ssh://git@%s/%s", host, path)
	default:
		// Plain host/path format
		baseURL = "https://" + strings.TrimSuffix(repo, ".git")
	}

	// Build go-getter git subdirectory URL
	return fmt.Sprintf("git::%s.git//policies?ref=%s", baseURL, version)
}

// ValidatePath checks if a policy path exists and is valid.
// It supports both directories (containing .rego files) and single .rego files.
func ValidatePath(path string) error {
	msg := i18n.Msg()
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf(msg.Errors.PolicyPathDoesNotExist, path)
	}
	if err != nil {
		return err
	}

	// If it's a file, check if it's a .rego file
	if !info.IsDir() {
		if !strings.HasSuffix(path, ".rego") {
			return fmt.Errorf(msg.Errors.FileMustBeRego, path)
		}
		return nil
	}

	// It's a directory - check for .rego files
	hasRego := false
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") {
			hasRego = true
			return filepath.SkipAll // Found at least one, stop walking
		}
		return nil
	})
	if err != nil {
		return err
	}

	if !hasRego {
		return fmt.Errorf(msg.Errors.NoRegoFilesInPolicyDirectory, path)
	}

	return nil
}

// DiscoverRegoFiles finds all .rego files from a path.
// If path is a directory, it recursively finds all .rego files.
// If path is a .rego file, it returns that single file.
func DiscoverRegoFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// If it's a single .rego file, return it directly
	msg := i18n.Msg()
	if !info.IsDir() {
		if strings.HasSuffix(path, ".rego") {
			return []string{path}, nil
		}
		return nil, fmt.Errorf(msg.Errors.FileMustBeRego, path)
	}

	// It's a directory - walk and find all .rego files
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// MatchPattern checks if an ID matches a wildcard pattern.
// The pattern supports `*` as a wildcard that matches zero or more characters.
// Examples:
//   - "rule:*" matches all rule IDs
//   - "rule:aliyun:ecs-*" matches "rule:aliyun:ecs-instance-no-public-ip"
//   - "rule:aliyun:*-multi-zone" matches "rule:aliyun:rds-instance-multi-zone"
func MatchPattern(pattern, id string) bool {
	// If pattern is exactly "*", match everything
	if pattern == "*" {
		return true
	}

	// If pattern doesn't contain "*", do exact match
	if !strings.Contains(pattern, "*") {
		return pattern == id
	}

	// Convert pattern to regex-like matching
	// Escape special regex characters except *
	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return true // "*" only
	}

	// Handle prefix match (no leading *)
	if !strings.HasPrefix(pattern, "*") {
		if !strings.HasPrefix(id, parts[0]) {
			return false
		}
		id = strings.TrimPrefix(id, parts[0])
		parts = parts[1:]
	}

	// Handle suffix match (no trailing *)
	if len(parts) > 0 && !strings.HasSuffix(pattern, "*") {
		lastPart := parts[len(parts)-1]
		if !strings.HasSuffix(id, lastPart) {
			return false
		}
		id = strings.TrimSuffix(id, lastPart)
		parts = parts[:len(parts)-1]
	}

	// Handle middle parts (substring matching)
	for _, part := range parts {
		if part == "" {
			continue // Consecutive *s
		}
		idx := strings.Index(id, part)
		if idx == -1 {
			return false
		}
		id = id[idx+len(part):]
	}

	return true
}
