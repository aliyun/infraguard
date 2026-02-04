package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
)

func main() {
	docsDir := "docs/docs"
	i18nBaseDir := "docs/i18n"

	// Get supported languages from i18n package
	expectedLanguages := i18n.GetSupportedLanguages()
	if len(expectedLanguages) == 0 {
		fmt.Fprintf(os.Stderr, "No supported languages found\n")
		os.Exit(1)
	}

	fmt.Printf("Supported languages: %v\n", expectedLanguages)
	fmt.Println()

	// Get all English documentation files (reference)
	enFiles, err := getAllMarkdownFiles(docsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading English docs: %v\n", err)
		os.Exit(1)
	}

	if len(enFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No English documentation files found in %s\n", docsDir)
		os.Exit(1)
	}

	fmt.Printf("Found %d English documentation files\n", len(enFiles))
	fmt.Println()

	// Separate policies and non-policies files for better reporting
	var policiesFiles []string
	var nonPoliciesFiles []string
	for _, f := range enFiles {
		relPath, err := filepath.Rel(docsDir, f)
		if err != nil {
			continue
		}
		if strings.HasPrefix(relPath, "policies/") {
			policiesFiles = append(policiesFiles, relPath)
		} else {
			nonPoliciesFiles = append(nonPoliciesFiles, relPath)
		}
	}

	fmt.Printf("  - Non-policies files: %d\n", len(nonPoliciesFiles))
	fmt.Printf("  - Policies files: %d\n", len(policiesFiles))
	fmt.Println()

	// Check each language (except English, which is the reference)
	hasErrors := false
	for _, lang := range expectedLanguages {
		if lang == "en" {
			continue // Skip English as it's the reference
		}

		langDir := filepath.Join(i18nBaseDir, lang, "docusaurus-plugin-content-docs", "current")
		langFiles, err := getAllMarkdownFiles(langDir)
		if err != nil {
			// If directory doesn't exist, treat as missing files
			if os.IsNotExist(err) {
				fmt.Printf("❌ Language '%s': Translation directory not found\n", lang)
				fmt.Printf("   Expected: %s\n", langDir)
				hasErrors = true
				continue
			}
			fmt.Fprintf(os.Stderr, "Error reading %s translations: %v\n", lang, err)
			hasErrors = true
			continue
		}

		// Convert to relative paths for comparison
		langFileMap := make(map[string]bool)
		for _, f := range langFiles {
			relPath, err := filepath.Rel(langDir, f)
			if err != nil {
				continue
			}
			langFileMap[relPath] = true
		}

		// Check for missing files
		var missingFiles []string
		for _, enFile := range enFiles {
			relPath, err := filepath.Rel(docsDir, enFile)
			if err != nil {
				continue
			}
			if !langFileMap[relPath] {
				missingFiles = append(missingFiles, relPath)
			}
		}

		// Check for extra files (not in English)
		var extraFiles []string
		enFileMap := make(map[string]bool)
		for _, enFile := range enFiles {
			relPath, err := filepath.Rel(docsDir, enFile)
			if err != nil {
				continue
			}
			enFileMap[relPath] = true
		}
		for _, langFile := range langFiles {
			relPath, err := filepath.Rel(langDir, langFile)
			if err != nil {
				continue
			}
			if !enFileMap[relPath] {
				extraFiles = append(extraFiles, relPath)
			}
		}

		// Separate missing files into policies and non-policies
		var missingPolicies []string
		var missingNonPolicies []string
		for _, f := range missingFiles {
			if strings.HasPrefix(f, "policies/") {
				missingPolicies = append(missingPolicies, f)
			} else {
				missingNonPolicies = append(missingNonPolicies, f)
			}
		}

		if len(missingFiles) > 0 || len(extraFiles) > 0 {
			hasErrors = true
			fmt.Printf("❌ Language '%s': Translation incomplete\n", lang)
			if len(missingNonPolicies) > 0 {
				fmt.Printf("   Missing non-policies files (%d):\n", len(missingNonPolicies))
				sort.Strings(missingNonPolicies)
				for _, f := range missingNonPolicies {
					fmt.Printf("     - %s\n", f)
				}
			}
			if len(missingPolicies) > 0 {
				fmt.Printf("   Missing policies files (%d):\n", len(missingPolicies))
				// Only show first 10 policies files to avoid overwhelming output
				sort.Strings(missingPolicies)
				for i, f := range missingPolicies {
					if i < 10 {
						fmt.Printf("     - %s\n", f)
					} else if i == 10 {
						fmt.Printf("     ... and %d more policies files\n", len(missingPolicies)-10)
						break
					}
				}
			}
			if len(extraFiles) > 0 {
				fmt.Printf("   Extra files (%d, not in English):\n", len(extraFiles))
				sort.Strings(extraFiles)
				for _, f := range extraFiles {
					fmt.Printf("     - %s\n", f)
				}
			}
		} else {
			fmt.Printf("✅ Language '%s': All translations present (%d files)\n", lang, len(langFiles))
		}
	}

	if hasErrors {
		fmt.Println()
		fmt.Println("❌ Documentation translation validation failed")
		fmt.Println("   Please ensure all documentation files have translations for all languages")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("✅ All documentation translations are complete")
}

// getAllMarkdownFiles recursively finds all .md files in a directory
func getAllMarkdownFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".md") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
