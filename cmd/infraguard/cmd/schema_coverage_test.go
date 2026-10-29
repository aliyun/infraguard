package cmd

import (
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
)

func TestSchemaUpdateRequiresCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{"ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY"} {
		t.Setenv(name, "")
	}
	err := schemaUpdateCmd.RunE(schemaUpdateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), i18n.Msg().Errors.ROSFailedLoadCredentials) {
		t.Fatalf("expected credentials error, got %v", err)
	}
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "short")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "test-secret")
	if err := schemaUpdateCmd.RunE(schemaUpdateCmd, nil); err == nil || !strings.Contains(err.Error(), i18n.Msg().Errors.ROSInvalidAccessKeyFormat) {
		t.Fatalf("expected invalid credential error, got %v", err)
	}
}
