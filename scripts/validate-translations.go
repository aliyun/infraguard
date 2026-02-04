package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TranslationFile represents a language translation YAML file
type TranslationFile struct {
	Path string
	Lang string
	Keys map[string]interface{}
}

func main() {
	localesDir := "pkg/i18n/locales"

	// Load all translation files
	files, err := loadTranslationFiles(localesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading translation files: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No translation files found in %s\n", localesDir)
		os.Exit(1)
	}

	// Use English as reference
	var reference *TranslationFile
	for _, f := range files {
		if f.Lang == "en" {
			reference = f
			break
		}
	}

	if reference == nil {
		fmt.Fprintf(os.Stderr, "English reference file not found\n")
		os.Exit(1)
	}

	// Validate all files against reference
	hasErrors := false
	for _, file := range files {
		if file.Lang == "en" {
			continue // Skip reference file
		}

		fmt.Printf("Validating %s.yaml...\n", file.Lang)

		missingKeys := findMissingKeys(reference.Keys, file.Keys, "")
		if len(missingKeys) > 0 {
			hasErrors = true
			fmt.Printf("  ❌ Missing keys in %s:\n", file.Lang)
			for _, key := range missingKeys {
				fmt.Printf("    - %s\n", key)
			}
		}

		extraKeys := findMissingKeys(file.Keys, reference.Keys, "")
		if len(extraKeys) > 0 {
			hasErrors = true
			fmt.Printf("  ⚠️  Extra keys in %s (not in reference):\n", file.Lang)
			for _, key := range extraKeys {
				fmt.Printf("    - %s\n", key)
			}
		}

		if len(missingKeys) == 0 && len(extraKeys) == 0 {
			fmt.Printf("  ✅ All keys present\n")
		}
	}

	if hasErrors {
		fmt.Println("\n❌ Validation failed")
		os.Exit(1)
	}

	fmt.Println("\n✅ All translation files are valid")
}

func loadTranslationFiles(dir string) ([]*TranslationFile, error) {
	var files []*TranslationFile

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		lang := strings.TrimSuffix(entry.Name(), ".yaml")
		path := filepath.Join(dir, entry.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}

		var keys map[string]interface{}
		if err := yaml.Unmarshal(data, &keys); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}

		files = append(files, &TranslationFile{
			Path: path,
			Lang: lang,
			Keys: keys,
		})
	}

	return files, nil
}

func findMissingKeys(reference, target map[string]interface{}, prefix string) []string {
	var missing []string

	for key, refValue := range reference {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		targetValue, exists := target[key]
		if !exists {
			missing = append(missing, fullKey)
			continue
		}

		// If the value is a nested map, recurse
		if refMap, ok := refValue.(map[string]interface{}); ok {
			if targetMap, ok := targetValue.(map[string]interface{}); ok {
				nestedMissing := findMissingKeys(refMap, targetMap, fullKey)
				missing = append(missing, nestedMissing...)
			} else {
				// Type mismatch
				missing = append(missing, fullKey)
			}
		}
	}

	return missing
}
