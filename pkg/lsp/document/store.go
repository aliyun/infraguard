// Package document manages text document state for the LSP server.
package document

import (
	"strings"
	"sync"
)

// Document represents an open text document.
type Document struct {
	URI        string
	LanguageID string
	Version    int
	Content    string
	Lines      []string
}

// LineCount returns the number of lines in the document.
func (d *Document) LineCount() int {
	return len(d.Lines)
}

// GetLine returns the content of a specific line (0-based).
func (d *Document) GetLine(line int) string {
	if line < 0 || line >= len(d.Lines) {
		return ""
	}
	return d.Lines[line]
}

// IsROSTemplate returns true if this document is a ROS template.
func (d *Document) IsROSTemplate() bool {
	if d.LanguageID == "ros-template-yaml" || d.LanguageID == "ros-template-json" {
		return true
	}
	if d.LanguageID == "yaml" || d.LanguageID == "json" {
		// Treat as ROS when: content already has format version, or URI suggests ROS file
		if strings.Contains(d.Content, "ROSTemplateFormatVersion") {
			return true
		}
		if strings.Contains(d.URI, ".ros.yml") || strings.Contains(d.URI, ".ros.yaml") || strings.Contains(d.URI, ".ros.json") {
			return true
		}
	}
	return false
}

// IsYAML returns true if the document is a YAML format.
func (d *Document) IsYAML() bool {
	return d.LanguageID == "ros-template-yaml" || d.LanguageID == "yaml"
}

// IsJSON returns true if the document is a JSON format.
func (d *Document) IsJSON() bool {
	return d.LanguageID == "ros-template-json" || d.LanguageID == "json"
}

// Store manages open documents.
type Store struct {
	mu   sync.RWMutex
	docs map[string]*Document
}

// NewStore creates a new document store.
func NewStore() *Store {
	return &Store{
		docs: make(map[string]*Document),
	}
}

// Open adds a new document to the store.
func (s *Store) Open(uri, languageID string, version int, content string) *Document {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc := &Document{
		URI:        uri,
		LanguageID: languageID,
		Version:    version,
		Content:    content,
		Lines:      splitLines(content),
	}
	s.docs[uri] = doc
	return doc
}

// Update updates the content of an existing document.
func (s *Store) Update(uri string, version int, content string) *Document {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, ok := s.docs[uri]
	if !ok {
		return nil
	}

	doc.Version = version
	doc.Content = content
	doc.Lines = splitLines(content)
	return doc
}

// Close removes a document from the store.
func (s *Store) Close(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, uri)
}

// Get returns the document for a given URI.
func (s *Store) Get(uri string) *Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.docs[uri]
}

func splitLines(content string) []string {
	if content == "" {
		return []string{""}
	}
	lines := strings.Split(content, "\n")
	return lines
}
