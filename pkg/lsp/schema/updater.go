package schema

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	ros "github.com/alibabacloud-go/ros-20190910/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

const (
	skipIfUpdatedWithin = time.Hour
	initialBackoff      = 4 * time.Second
	maxBackoff          = 32 * time.Second
)

// FetchOptions configures the schema fetch behavior.
type FetchOptions struct {
	// OutputPath is the file path to save the schema to.
	// If empty, saves to the default local schema path (~/.infraguard/schemas/).
	OutputPath string

	// Logger is a printf-style function for progress logging.
	// If nil, defaults to log.Printf.
	Logger func(format string, args ...interface{})
}

func (o *FetchOptions) logf(format string, args ...interface{}) {
	if o != nil && o.Logger != nil {
		o.Logger(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (o *FetchOptions) outputPath() string {
	if o != nil {
		return o.OutputPath
	}
	return ""
}

// FetchAndSave fetches the latest schema from ROS API and saves it locally.
// It performs incremental updates: skips resources updated within 1 hour,
// saves after each resource, and retries with exponential backoff on throttling.
func FetchAndSave(client *ros.Client, opts *FetchOptions) (int, error) {
	sf := loadExistingSchema(opts.outputPath())
	if sf == nil {
		sf = &SchemaFile{
			ResourceTypes: make(map[string]*ResourceType),
		}
	}
	sf.Version = time.Now().Format("2006-01-02")

	typeNames, err := listAllResourceTypes(client)
	if err != nil {
		return 0, fmt.Errorf("list resource types: %w", err)
	}

	opts.logf("Found %d resource types", len(typeNames))

	for i, name := range typeNames {
		if rt, ok := sf.ResourceTypes[name]; ok && rt.UpdatedAt != "" {
			if t, err := time.Parse(time.RFC3339, rt.UpdatedAt); err == nil {
				if time.Since(t) < skipIfUpdatedWithin {
					opts.logf("[%d/%d] Skipping %s (updated %s ago)",
						i+1, len(typeNames), name, time.Since(t).Truncate(time.Second))
					continue
				}
			}
		}

		opts.logf("[%d/%d] Fetching %s...", i+1, len(typeNames), name)

		rt, err := fetchWithRetry(client, name, opts)
		if err != nil {
			opts.logf("  WARNING: failed to get %s: %v, skipping", name, err)
			continue
		}

		rt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		sf.ResourceTypes[name] = rt

		if err := saveSchema(sf, opts.outputPath()); err != nil {
			opts.logf("  WARNING: failed to save schema: %v", err)
		}
	}

	return len(sf.ResourceTypes), nil
}

func fetchWithRetry(client *ros.Client, typeName string, opts *FetchOptions) (*ResourceType, error) {
	rt, err := fetchResourceType(client, typeName)
	if err == nil {
		return rt, nil
	}
	if !isThrottlingError(err) {
		return nil, err
	}

	for backoff := initialBackoff; backoff <= maxBackoff; backoff *= 2 {
		opts.logf("  Throttled, retrying in %s...", backoff)
		time.Sleep(backoff)

		rt, err = fetchResourceType(client, typeName)
		if err == nil {
			return rt, nil
		}
		if !isThrottlingError(err) {
			return nil, err
		}
	}

	return nil, err
}

func isThrottlingError(err error) bool {
	if sdkErr, ok := err.(*tea.SDKError); ok {
		return strings.Contains(tea.StringValue(sdkErr.Code), "Throttling")
	}
	return strings.Contains(err.Error(), "Throttling")
}

func loadExistingSchema(outputPath string) *SchemaFile {
	var data []byte
	var err error

	if outputPath != "" {
		data, err = os.ReadFile(outputPath)
	} else {
		path, pathErr := localSchemaPath()
		if pathErr != nil {
			return nil
		}
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return nil
	}

	var sf SchemaFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil
	}
	if sf.ResourceTypes == nil {
		sf.ResourceTypes = make(map[string]*ResourceType)
	}
	return &sf
}

func saveSchema(sf *SchemaFile, outputPath string) error {
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal schema: %w", err)
	}

	if outputPath != "" {
		return os.WriteFile(outputPath, data, 0644)
	}
	return SaveLocal(data)
}

func listAllResourceTypes(client *ros.Client) ([]string, error) {
	req := &ros.ListResourceTypesRequest{
		EntityType: tea.String("All"),
	}
	resp, err := client.ListResourceTypes(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, fmt.Errorf("empty response body")
	}

	var allTypes []string
	for _, rt := range resp.Body.ResourceTypes {
		if rt != nil {
			allTypes = append(allTypes, *rt)
		}
	}

	sort.Strings(allTypes)
	return allTypes, nil
}

func fetchResourceType(client *ros.Client, typeName string) (*ResourceType, error) {
	req := &ros.GetResourceTypeRequest{
		ResourceType: tea.String(typeName),
	}
	resp, err := client.GetResourceType(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, fmt.Errorf("empty response for %s", typeName)
	}

	rt := &ResourceType{
		Properties: make(map[string]*Property),
		Attributes: make(map[string]*Attribute),
	}

	if resp.Body.Description != nil {
		rt.Description = *resp.Body.Description
	}

	if resp.Body.Properties != nil {
		for propName, propVal := range resp.Body.Properties {
			if p := parsePropertyValue(propVal); p != nil {
				rt.Properties[propName] = p
			}
		}
	}

	if resp.Body.Attributes != nil {
		for attrName, attrVal := range resp.Body.Attributes {
			if a := parseAttributeValue(attrVal); a != nil {
				rt.Attributes[attrName] = a
			}
		}
	}

	return rt, nil
}

func parsePropertyValue(val interface{}) *Property {
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil
	}
	p := &Property{Updatable: true}
	if v, ok := m["Type"].(string); ok {
		p.Type = v
	}
	if v, ok := m["Required"].(bool); ok {
		p.Required = v
	}
	if v, ok := m["Immutable"].(bool); ok {
		p.Updatable = !v
	}
	if v, ok := m["Description"].(string); ok {
		p.Description = v
	}

	if constraints, ok := m["Constraints"].([]interface{}); ok {
		p.Constraints = parseConstraints(constraints)
	}

	if schema, ok := m["Schema"].(map[string]interface{}); ok {
		p.Properties = parseSchemaProperties(schema)
	}

	return p
}

func parseConstraints(constraints []interface{}) *Constraint {
	c := &Constraint{}
	hasConstraint := false
	for _, item := range constraints {
		cm, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if _, has := cm["CustomConstraint"]; has {
			continue
		}
		if av, ok := cm["AllowedValues"].([]interface{}); ok {
			c.AllowedValues = av
			hasConstraint = true
		}
		if ap, ok := cm["AllowedPattern"].(string); ok {
			c.AllowedPattern = ap
			hasConstraint = true
		}
		if r, ok := cm["Range"].(map[string]interface{}); ok {
			if min, ok := toFloat64(r["Min"]); ok {
				c.MinValue = &min
				hasConstraint = true
			}
			if max, ok := toFloat64(r["Max"]); ok {
				c.MaxValue = &max
				hasConstraint = true
			}
		}
		if l, ok := cm["Length"].(map[string]interface{}); ok {
			if min, ok := toInt(l["Min"]); ok {
				c.MinLength = &min
				hasConstraint = true
			}
			if max, ok := toInt(l["Max"]); ok {
				c.MaxLength = &max
				hasConstraint = true
			}
		}
	}
	if !hasConstraint {
		return nil
	}
	return c
}

func parseSchemaProperties(schema map[string]interface{}) map[string]*Property {
	props := make(map[string]*Property)
	for key, val := range schema {
		if key == "*" {
			subMap, ok := val.(map[string]interface{})
			if !ok {
				continue
			}
			innerSchema, ok := subMap["Schema"].(map[string]interface{})
			if !ok {
				continue
			}
			for innerKey, innerVal := range innerSchema {
				if p := parsePropertyValue(innerVal); p != nil {
					props[innerKey] = p
				}
			}
			continue
		}
		if p := parsePropertyValue(val); p != nil {
			props[key] = p
		}
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func parseAttributeValue(val interface{}) *Attribute {
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil
	}
	a := &Attribute{}
	if v, ok := m["Description"].(string); ok {
		a.Description = v
	}
	return a
}
