package mapper

import (
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
)

// MapTerraformViolations maps OPA violations to source locations using __meta__ fields
// embedded in the Terraform OPA input. The __meta__ fields contain the filename and line
// number for each resource block, allowing violations to be traced back to their source.
func MapTerraformViolations(violations []models.OPAViolation, opaInput map[string]interface{}, dir string, lang string) []models.RichViolation {
	// Extract language code prefix (e.g., "ja-JP" -> "ja", "fr-FR" -> "fr")
	langCode := lang
	if parts := strings.Split(lang, "-"); len(parts) > 0 {
		langCode = strings.ToLower(parts[0])
	}

	resources, _ := opaInput["resources"].(map[string]interface{})

	var rich []models.RichViolation
	for _, v := range violations {
		rv := models.RichViolation{
			Severity:          v.Meta.Severity,
			ID:                v.ID,
			ResourceID:        v.ResourceID,
			ViolationPath:     pathToStrings(v.ViolationPath),
			File:              dir,
			Line:              1, // Default to line 1 if mapping fails
			Reason:            i18n.FormatMessage(v.Meta.Reason, langCode),
			Recommendation:    i18n.FormatMessage(v.Meta.Recommendation, langCode),
			ReasonRaw:         v.Meta.Reason,
			RecommendationRaw: v.Meta.Recommendation,
		}

		line, filename := findTerraformResourceLocation(v.ResourceID, resources)
		if line > 0 {
			rv.Line = line
			if filename != "" {
				rv.File = filepath.Join(dir, filename)
			}
			rv.Snippet, rv.SnippetLines = getSnippetWithContext(rv.File, line, SnippetContextLines)
		}

		rich = append(rich, rv)
	}
	return rich
}

// findTerraformResourceLocation looks up a resource's source location from the __meta__ field.
// The resourceID is expected in "resource_type.resource_name" format (e.g., "alicloud_instance.web").
// Returns the line number and filename from the __meta__ map, or (0, "") if not found.
func findTerraformResourceLocation(resourceID string, resources map[string]interface{}) (int, string) {
	if resources == nil {
		return 0, ""
	}

	parts := strings.SplitN(resourceID, ".", 2)
	if len(parts) != 2 {
		return 0, ""
	}
	resType := parts[0]
	resName := parts[1]

	typeMap, ok := resources[resType].(map[string]interface{})
	if !ok {
		return 0, ""
	}
	instance, ok := typeMap[resName].(map[string]interface{})
	if !ok {
		return 0, ""
	}
	meta, ok := instance["__meta__"].(map[string]interface{})
	if !ok {
		return 0, ""
	}

	line := 0
	filename := ""
	if l, ok := meta["line"].(float64); ok {
		line = int(l)
	} else if l, ok := meta["line"].(int); ok {
		line = l
	}
	if f, ok := meta["filename"].(string); ok {
		filename = f
	}
	return line, filename
}
