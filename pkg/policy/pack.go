// Package policy manages policy library operations including rule and pack parsing.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ParsePackFromContentWithPath extracts pack metadata from rego content.
// The baseDir is used to auto-generate the pack ID prefix from the file path.
func ParsePackFromContentWithPath(content, filePath, baseDir string) (*models.Pack, error) {
	// Extract package name
	packageName := extractPackageName(content)
	if packageName == "" {
		return nil, nil // Not a valid rego file
	}

	// Build the query for this specific package's pack_meta
	query := fmt.Sprintf("data.%s.pack_meta", packageName)

	ctx := context.Background()
	r := rego.New(
		rego.Query(query),
		rego.Module(filePath, content),
	)

	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		// File doesn't have pack_meta or has syntax errors
		return nil, nil
	}

	results, err := preparedQuery.Eval(ctx)
	if err != nil || len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil
	}

	// Parse pack_meta from results
	expr := results[0].Expressions[0]
	if expr.Value == nil {
		return nil, nil
	}

	pack, err := parsePackMeta(expr.Value, filePath, packageName, baseDir)
	if err != nil {
		msg := i18n.Msg()
		return nil, fmt.Errorf(msg.Errors.ParsePackMeta, err)
	}

	return pack, nil
}

// parsePackMeta converts OPA result to Pack struct.
// ID is auto-generated from the file path if not specified in pack_meta.
func parsePackMeta(value interface{}, filePath, packageName, baseDir string) (*models.Pack, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var rawMeta struct {
		ID          string      `json:"id"`
		Name        interface{} `json:"name"`
		Description interface{} `json:"description"`
		Rules       []string    `json:"rules"`
	}

	if err := json.Unmarshal(data, &rawMeta); err != nil {
		return nil, err
	}

	// Auto-generate ID from file path if not specified
	packID := rawMeta.ID
	if packID == "" {
		// Extract name from filename (without .rego extension)
		baseName := filepath.Base(filePath)
		name := strings.TrimSuffix(baseName, ".rego")
		// Convert snake_case to kebab-case
		name = strings.ReplaceAll(name, "_", "-")
		packID = GeneratePackID(filePath, baseDir, name)
	} else {
		// If ID is specified but doesn't have prefix, add it
		if !strings.HasPrefix(packID, "pack:") {
			name := packID
			packID = GeneratePackID(filePath, baseDir, name)
		}
	}

	// Auto-generate rule ID prefixes for rules list
	var ruleIDs []string
	for _, ruleRef := range rawMeta.Rules {
		if strings.HasPrefix(ruleRef, "rule:") {
			// Already has prefix
			ruleIDs = append(ruleIDs, ruleRef)
		} else {
			// Generate prefix based on pack's location
			// Assume rules are in the same provider directory
			prefix := GenerateIDPrefix(filePath, baseDir, "rule")
			// Remove "pack:" and add "rule:"
			prefix = strings.Replace(prefix, "pack:", "rule:", 1)
			ruleIDs = append(ruleIDs, prefix+ruleRef)
		}
	}

	pack := &models.Pack{
		ID:          packID,
		Name:        parseI18nString(rawMeta.Name),
		Description: parseI18nString(rawMeta.Description),
		RuleIDs:     ruleIDs,
		FilePath:    filePath,
		PackageName: packageName,
	}

	return pack, nil
}

// DiscoverPacks finds all packs in a directory.
func DiscoverPacks(dir string) ([]*models.Pack, error) {
	var packs []*models.Pack

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files that can't be read
		}

		pack, err := ParsePackFromContentWithPath(string(content), path, dir)
		if err != nil {
			// Log warning but continue
			return nil
		}
		if pack != nil {
			packs = append(packs, pack)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return packs, nil
}
