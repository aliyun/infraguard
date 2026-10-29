package ros

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
)

func TestPreviewRejectsInvalidInputBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	for _, key := range []string{"ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY", "ALIBABA_CLOUD_SECURITY_TOKEN"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(path, []byte("ROSTemplateFormatVersion: '2015-09-01'\nParameters:\n  Count:\n    Type: Number\nResources: {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(ModePreview, filepath.Join(dir, "missing"), nil); err == nil {
		t.Fatal("missing template accepted")
	}
	if _, _, err := Load(ModePreview, path, map[string]interface{}{"Unknown": "value"}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
	if _, _, err := Load(ModePreview, path, nil); err == nil {
		t.Fatal("missing credentials accepted")
	}
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "short")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "test-secret")
	if _, _, err := Load(ModePreview, path, nil); err == nil || !strings.Contains(err.Error(), i18n.Msg().Errors.ROSInvalidAccessKeyFormat) {
		t.Fatalf("invalid credentials accepted: %v", err)
	}
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("Parameters: {}\nResources: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(ModePreview, invalid, nil); err == nil {
		t.Fatal("invalid template structure accepted")
	}
	if _, _, err := Load(ModeStatic, path, map[string]interface{}{"Count": "not-number"}); err == nil {
		t.Fatal("invalid number accepted")
	}
}
