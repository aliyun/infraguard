// Package schema provides ROS resource type schema management.
package schema

// SchemaFile represents the top-level schema file structure.
type SchemaFile struct {
	Version       string                   `json:"version"`
	ResourceTypes map[string]*ResourceType `json:"resourceTypes"`
}

// ResourceType represents a single ROS resource type definition.
type ResourceType struct {
	Description string                `json:"description"`
	Properties  map[string]*Property  `json:"properties,omitempty"`
	Attributes  map[string]*Attribute `json:"attributes,omitempty"`
	UpdatedAt   string                `json:"updatedAt,omitempty"`
}

// Property represents a resource property definition.
type Property struct {
	Type        string               `json:"type"`
	Required    bool                 `json:"required"`
	Updatable   bool                 `json:"updatable"`
	Description string               `json:"description"`
	Constraints *Constraint          `json:"constraints,omitempty"`
	Properties  map[string]*Property `json:"properties,omitempty"`
}

// Attribute represents a resource attribute (output) definition.
type Attribute struct {
	Description string `json:"description"`
}

// Constraint represents optional constraints on a property value.
type Constraint struct {
	AllowedValues  []interface{} `json:"allowedValues,omitempty"`
	AllowedPattern string        `json:"allowedPattern,omitempty"`
	MinValue       *float64      `json:"minValue,omitempty"`
	MaxValue       *float64      `json:"maxValue,omitempty"`
	MinLength      *int          `json:"minLength,omitempty"`
	MaxLength      *int          `json:"maxLength,omitempty"`
}

// AssociationPropertyFile represents the top-level schema file for AssociationProperty values.
type AssociationPropertyFile struct {
	Version               string                          `json:"version"`
	AssociationProperties map[string]*AssociationProperty `json:"associationProperties"`
}

// AssociationProperty represents a single AssociationProperty definition.
type AssociationProperty struct {
	Description string                              `json:"description"`
	Category    string                              `json:"category"`
	Metadata    map[string]*AssociationPropertyMeta `json:"metadata,omitempty"`
}

// AssociationPropertyMeta represents a metadata key for an AssociationProperty.
type AssociationPropertyMeta struct {
	Description string `json:"description"`
	// ValueType indicates the expected type of this metadata value.
	// Common values: "String", "Boolean", "Integer", "Number", "Map", "List",
	// "String/Map", "${Parameter}" (value supports ${ParameterName} references).
	ValueType string `json:"valueType,omitempty"`
}
