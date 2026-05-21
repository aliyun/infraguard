package terraform

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

type ParsedConfig struct {
	Files map[string]*hcl.File
	Dir   string
}

func discoverTFFiles(dir string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".tf") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	return files, nil
}

func parseTFDir(dir string) (*ParsedConfig, hcl.Diagnostics) {
	files, err := discoverTFFiles(dir)
	if err != nil {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Failed to discover .tf files",
			Detail:   err.Error(),
		}}
	}

	if len(files) == 0 {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "No .tf files found",
			Detail:   "Directory " + dir + " contains no .tf files",
		}}
	}

	parser := hclparse.NewParser()
	var allDiags hcl.Diagnostics
	parsedFiles := make(map[string]*hcl.File)

	for _, file := range files {
		var f *hcl.File
		var diags hcl.Diagnostics
		f, diags = parser.ParseHCLFile(file)
		allDiags = append(allDiags, diags...)
		if f != nil {
			parsedFiles[file] = f
		}
	}

	return &ParsedConfig{Files: parsedFiles, Dir: dir}, allDiags
}
