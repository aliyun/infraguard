package loader

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
)

func TestInputFileFormatsAndFailures(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kv := write("params.tfvars", "# comment\n\nname = \"old\"\nsecret = a=b\ninvalid line\n")
	json := write("params.json", `{"name":"json","count":2}`)
	yaml := write("params.data", "enabled: true\nregion: cn-hangzhou\n")
	got, err := ParseInputValues([]string{kv, json, yaml, "name=last"})
	want := models.TemplateParams{"name": "last", "secret": "a=b", "count": float64(2), "enabled": true, "region": "cn-hangzhou"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("values=%#v err=%v", got, err)
	}
	for _, tc := range []struct{ name, path string }{
		{"missing", filepath.Join(dir, "missing.json")},
		{"invalid JSON", write("bad.json", "{invalid")},
		{"invalid YAML", write("bad.yaml", "[invalid")},
		{"unknown format", write("bad.data", "[invalid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseInputValues([]string{tc.path}); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	if _, err := ParseInputValues([]string{"invalid"}); err == nil {
		t.Fatal("invalid argument accepted")
	}
}
