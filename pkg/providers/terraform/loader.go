package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Load parses, evaluates, and converts a Terraform directory (or single .tf file)
// into the OPA input format used by infraguard policies.
func Load(path string, inputVars map[string]interface{}) (map[string]interface{}, error) {
	dir, err := resolveDir(path)
	if err != nil {
		return nil, err
	}

	parsed, diags := parseTFDir(dir)
	if diags.HasErrors() {
		return nil, fmt.Errorf("HCL parse error: %s", diags.Error())
	}

	if inputVars == nil {
		inputVars = make(map[string]interface{})
	}

	result, err := evaluate(parsed, inputVars)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	return convertToOPAInput(result), nil
}

// LoadContent parses, evaluates, and converts a single in-memory Terraform file
// into the OPA input format. It avoids the filesystem so it can run in wasm.
func LoadContent(filename, content string, inputVars map[string]interface{}) (map[string]interface{}, error) {
	if filename == "" {
		filename = "main.tf"
	}
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL([]byte(content), filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("HCL parse error: %s", diags.Error())
	}

	parsed := &ParsedConfig{Files: map[string]*hcl.File{filename: f}, Dir: "."}

	if inputVars == nil {
		inputVars = make(map[string]interface{})
	}

	result, err := evaluate(parsed, inputVars)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	return convertToOPAInput(result), nil
}

// resolveDir determines the Terraform project directory from a path.
// If path is a directory, it is returned as-is.
// If path is a .tf file, the parent directory is returned.
func resolveDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("path not found: %s", path)
	}

	if info.IsDir() {
		return path, nil
	}

	if strings.HasSuffix(path, ".tf") {
		return filepath.Dir(path), nil
	}

	return "", fmt.Errorf("not a Terraform file or directory: %s", path)
}

// IsTerraformFile reports whether path has a .tf extension.
func IsTerraformFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".tf")
}

// IsTerraformDir reports whether path is a directory containing at least one .tf file.
func IsTerraformDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	files, err := discoverTFFiles(path)
	return err == nil && len(files) > 0
}
