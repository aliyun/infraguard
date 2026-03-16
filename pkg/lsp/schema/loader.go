package schema

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//go:embed data/ros_resources.json
var embeddedSchema embed.FS

//go:embed data/ros_association_properties.json
var embeddedAssocSchema embed.FS

const (
	embeddedSchemaPath      = "data/ros_resources.json"
	embeddedAssocSchemaPath = "data/ros_association_properties.json"
	localSchemaDir          = ".infraguard/schemas"
	localSchemaFile         = "ros_resources.json"
)

// Registry provides access to ROS resource type schema data.
type Registry struct {
	mu          sync.RWMutex
	schema      *SchemaFile
	assocSchema *AssociationPropertyFile
}

var defaultRegistry *Registry
var registryOnce sync.Once

// DefaultRegistry returns the singleton schema registry.
func DefaultRegistry() *Registry {
	registryOnce.Do(func() {
		defaultRegistry = &Registry{}
		if err := defaultRegistry.Load(); err != nil {
			log.Printf("[Schema] failed to load schema: %v, using empty registry", err)
			defaultRegistry.schema = &SchemaFile{
				ResourceTypes: make(map[string]*ResourceType),
			}
		}
		if err := defaultRegistry.LoadAssociationProperties(); err != nil {
			log.Printf("[Schema] failed to load association properties schema: %v", err)
			defaultRegistry.assocSchema = &AssociationPropertyFile{
				AssociationProperties: make(map[string]*AssociationProperty),
			}
		}
	})
	return defaultRegistry
}

// Load loads the schema with priority: local file > embedded file.
func (r *Registry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	localPath, err := localSchemaPath()
	if err == nil {
		if data, err := os.ReadFile(localPath); err == nil {
			var sf SchemaFile
			if err := json.Unmarshal(data, &sf); err == nil {
				r.schema = &sf
				log.Printf("[Schema] loaded from local file: %s (%d resource types)", localPath, len(sf.ResourceTypes))
				return nil
			}
			log.Printf("[Schema] local file exists but failed to parse: %s", localPath)
		}
	}

	data, err := embeddedSchema.ReadFile(embeddedSchemaPath)
	if err != nil {
		return fmt.Errorf("read embedded schema: %w", err)
	}

	var sf SchemaFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("parse embedded schema: %w", err)
	}

	r.schema = &sf
	log.Printf("[Schema] loaded from embedded data (%d resource types)", len(sf.ResourceTypes))
	return nil
}

// LoadFromData loads schema from raw JSON data.
func (r *Registry) LoadFromData(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var sf SchemaFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("parse schema data: %w", err)
	}

	r.schema = &sf
	return nil
}

// Version returns the schema version string.
func (r *Registry) Version() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.schema == nil {
		return ""
	}
	return r.schema.Version
}

// GetResourceType returns the definition for a given resource type name.
func (r *Registry) GetResourceType(typeName string) *ResourceType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.schema == nil {
		return nil
	}
	return r.schema.ResourceTypes[typeName]
}

// HasResourceType checks whether a resource type exists in the schema.
func (r *Registry) HasResourceType(typeName string) bool {
	return r.GetResourceType(typeName) != nil
}

// AllResourceTypeNames returns a sorted list of all resource type names.
func (r *Registry) AllResourceTypeNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.schema == nil {
		return nil
	}

	names := make([]string, 0, len(r.schema.ResourceTypes))
	for name := range r.schema.ResourceTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SearchResourceTypes returns resource type names matching a query (case-insensitive contains).
func (r *Registry) SearchResourceTypes(query string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.schema == nil {
		return nil
	}

	queryUpper := strings.ToUpper(query)
	var matches []string
	for name := range r.schema.ResourceTypes {
		if strings.Contains(strings.ToUpper(name), queryUpper) {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches
}

// GetProperties returns the properties for a given resource type.
func (r *Registry) GetProperties(typeName string) map[string]*Property {
	rt := r.GetResourceType(typeName)
	if rt == nil {
		return nil
	}
	return rt.Properties
}

// GetProperty returns a specific property of a resource type.
func (r *Registry) GetProperty(typeName, propName string) *Property {
	props := r.GetProperties(typeName)
	if props == nil {
		return nil
	}
	return props[propName]
}

// GetAttributes returns the attributes for a given resource type.
func (r *Registry) GetAttributes(typeName string) map[string]*Attribute {
	rt := r.GetResourceType(typeName)
	if rt == nil {
		return nil
	}
	return rt.Attributes
}

// RequiredProperties returns the names of required properties for a resource type.
func (r *Registry) RequiredProperties(typeName string) []string {
	props := r.GetProperties(typeName)
	if props == nil {
		return nil
	}

	var required []string
	for name, prop := range props {
		if prop.Required {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	return required
}

// ResourceTypeCount returns the total number of resource types.
func (r *Registry) ResourceTypeCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.schema == nil {
		return 0
	}
	return len(r.schema.ResourceTypes)
}

// SaveLocal saves the given schema data to the local schema path.
func SaveLocal(data []byte) error {
	dir, err := localSchemaDir_()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create schema directory: %w", err)
	}
	path := filepath.Join(dir, localSchemaFile)
	return os.WriteFile(path, data, 0644)
}

// LoadAssociationProperties loads the association properties schema from embedded data.
func (r *Registry) LoadAssociationProperties() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := embeddedAssocSchema.ReadFile(embeddedAssocSchemaPath)
	if err != nil {
		return fmt.Errorf("read embedded association properties schema: %w", err)
	}

	var af AssociationPropertyFile
	if err := json.Unmarshal(data, &af); err != nil {
		return fmt.Errorf("parse association properties schema: %w", err)
	}

	r.assocSchema = &af
	log.Printf("[Schema] loaded association properties (%d entries)", len(af.AssociationProperties))
	return nil
}

// GetAssociationProperty returns the definition for a given AssociationProperty name.
func (r *Registry) GetAssociationProperty(name string) *AssociationProperty {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.assocSchema == nil {
		return nil
	}
	return r.assocSchema.AssociationProperties[name]
}

// AllAssociationPropertyNames returns a sorted list of all AssociationProperty names.
func (r *Registry) AllAssociationPropertyNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.assocSchema == nil {
		return nil
	}

	names := make([]string, 0, len(r.assocSchema.AssociationProperties))
	for name := range r.assocSchema.AssociationProperties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SearchAssociationProperties returns association property names matching a query (case-insensitive contains).
func (r *Registry) SearchAssociationProperties(query string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.assocSchema == nil {
		return nil
	}

	queryUpper := strings.ToUpper(query)
	var matches []string
	for name := range r.assocSchema.AssociationProperties {
		if strings.Contains(strings.ToUpper(name), queryUpper) {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches
}

func localSchemaPath() (string, error) {
	dir, err := localSchemaDir_()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, localSchemaFile), nil
}

func localSchemaDir_() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, localSchemaDir), nil
}
