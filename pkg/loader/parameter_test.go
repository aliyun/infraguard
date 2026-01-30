// Package loader handles generic template input parsing.
package loader

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
)

func TestParseInputValues(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	kvFile := filepath.Join(tmpDir, "params.txt")
	os.WriteFile(kvFile, []byte("Key3=Value3\nKey4=Value4"), 0644)

	jsonFile := filepath.Join(tmpDir, "params.json")
	os.WriteFile(jsonFile, []byte(`{"Key5": "Value5"}`), 0644)

	tests := []struct {
		name    string
		inputs  []string
		want    models.TemplateParams
		wantErr bool
	}{
		{
			name:   "key=value format",
			inputs: []string{"Key1=Value1", "Key2=Value2"},
			want:   models.TemplateParams{"Key1": "Value1", "Key2": "Value2"},
		},
		{
			name:   "JSON format",
			inputs: []string{`{"Key1": "Value1", "Key2": 2}`},
			want:   models.TemplateParams{"Key1": "Value1", "Key2": float64(2)},
		},
		{
			name:   "KV file format",
			inputs: []string{kvFile},
			want:   models.TemplateParams{"Key3": "Value3", "Key4": "Value4"},
		},
		{
			name:   "JSON file format",
			inputs: []string{jsonFile},
			want:   models.TemplateParams{"Key5": "Value5"},
		},
		{
			name:   "Mixed formats and overrides",
			inputs: []string{"Key1=OldValue", jsonFile, "Key1=NewValue"},
			want:   models.TemplateParams{"Key1": "NewValue", "Key5": "Value5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInputValues(tt.inputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseInputValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseInputValues() = %v, want %v", got, tt.want)
			}
		})
	}
}
