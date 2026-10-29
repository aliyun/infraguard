package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/spf13/cobra"
)

func TestPolicyCatalogCommands(t *testing.T) {
	oldIndex, oldType := policy.EmbeddedIndex, policyListType
	t.Cleanup(func() { policy.EmbeddedIndex, policyListType = oldIndex, oldType })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	rule := &models.Rule{ID: "rule:aliyun:sample", Name: models.I18nString{"en": "Sample"}, Severity: "high", IaCTypes: []string{"ros"}, ResourceTypes: []string{"ALIYUN::ECS::Instance"}, Content: "package sample"}
	pack := &models.Pack{ID: "pack:aliyun:sample", Name: models.I18nString{"en": "Sample Pack"}, RuleIDs: []string{rule.ID}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule}, PackList: []*models.Pack{pack}}
	cmd := &cobra.Command{}
	cmd.Flags().String("type", "", "")
	for _, kind := range []string{"", "rule", "pack"} {
		policyListType = kind
		if err := runPolicyList(cmd, nil); err != nil {
			t.Errorf("list %q: %v", kind, err)
		}
	}
	if err := cmd.Flags().Set("type", "bad"); err != nil {
		t.Fatal(err)
	}
	policyListType = "bad"
	if err := runPolicyList(cmd, nil); err == nil {
		t.Fatal("invalid type accepted")
	}
	for _, id := range []string{rule.ID, pack.ID} {
		if err := runPolicyGet(nil, []string{id}); err != nil {
			t.Errorf("get %s: %v", id, err)
		}
	}
	for _, id := range []string{"rule:aliyun:missing", "pack:aliyun:missing", "missing"} {
		if err := runPolicyGet(nil, []string{id}); err == nil {
			t.Errorf("missing %s accepted", id)
		}
	}
}

func TestPolicyCatalogReportsUnresolvedPackRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	oldIndex, oldType, oldStdout := policy.EmbeddedIndex, policyListType, os.Stdout
	t.Cleanup(func() { policy.EmbeddedIndex, policyListType, os.Stdout = oldIndex, oldType, oldStdout })
	pack := &models.Pack{ID: "pack:aliyun:sample", RuleIDs: []string{"rule:aliyun:missing"}}
	policy.EmbeddedIndex = &models.PolicyIndex{PackList: []*models.Pack{pack}}
	output, err := os.Create(filepath.Join(home, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	os.Stdout = output
	policyListType = "rule"
	cmd := &cobra.Command{}
	cmd.Flags().String("type", "", "")
	if err := runPolicyList(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyGet(nil, []string{pack.ID}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil || !strings.Contains(string(data), "rule:aliyun:missing") {
		t.Fatalf("unresolved pack output: %q %v", data, err)
	}
}

func TestPolicyValidateFormatAndClean(t *testing.T) {
	oldWrite, oldDiff, oldForce := formatWrite, formatDiff, cleanForce
	t.Cleanup(func() { formatWrite, formatDiff, cleanForce = oldWrite, oldDiff, oldForce })
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(root, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(root, "isolated-workspace"))
	valid, err := os.ReadFile("../../../pkg/policy/testdata/validate/valid/valid-rule.rego")
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := os.ReadFile("../../../pkg/policy/testdata/validate/invalid/missing-name.rego")
	if err != nil {
		t.Fatal(err)
	}
	validPath := filepath.Join(root, "valid.rego")
	invalidPath := filepath.Join(root, "invalid.rego")
	if err := os.WriteFile(validPath, valid, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPath, invalid, 0644); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyValidate(nil, []string{validPath}); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyValidate(nil, []string{invalidPath}); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if err := runPolicyValidate(nil, []string{filepath.Join(root, "missing")}); err == nil {
		t.Fatal("missing path accepted")
	}
	emptyDir := filepath.Join(root, "empty")
	if err := os.Mkdir(emptyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyValidate(nil, []string{emptyDir}); err != nil {
		t.Fatalf("empty policy directory: %v", err)
	}
	if err := runPolicyFormat(nil, []string{emptyDir}); err != nil {
		t.Fatalf("format empty directory: %v", err)
	}
	unknown := filepath.Join(emptyDir, "helper.rego")
	if err := os.WriteFile(unknown, []byte("package helpers\nvalue := true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyValidate(nil, []string{emptyDir}); err != nil {
		t.Fatalf("unrelated helper module should be skipped: %v", err)
	}
	formatWrite, formatDiff = false, true
	unformatted := filepath.Join(root, "unformatted.rego")
	if err := os.WriteFile(unformatted, []byte("package example\n\nhello:=true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyFormat(nil, []string{unformatted}); err == nil {
		t.Fatal("unformatted rule accepted")
	}
	formatWrite, formatDiff = true, false
	if err := runPolicyFormat(nil, []string{unformatted}); err != nil {
		t.Fatal(err)
	}
	formatWrite = false
	if err := runPolicyFormat(nil, []string{unformatted}); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(root, "malformed.rego")
	if err := os.WriteFile(malformed, []byte("package infraguard.rules.aliyun.example\n???\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyValidate(nil, []string{malformed}); err == nil {
		t.Fatal("malformed policy passed validation")
	}
	for _, write := range []bool{false, true} {
		formatWrite = write
		if err := runPolicyFormat(nil, []string{malformed}); err == nil {
			t.Fatalf("malformed Rego accepted with write=%v", write)
		}
	}
	cleanForce = true
	if err := runPolicyClean(nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyUpdateFromLocalRepository(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_COUNT", "0")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		command := exec.Command("git", args...)
		command.Dir = repo
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-b", "feat/test-policy-source")
	git("config", "user.email", "test@example.com")
	git("config", "user.name", "Test User")
	source := filepath.Join(repo, "policies", "aliyun", "rules", "sample.rego")
	if err := os.MkdirAll(filepath.Dir(source), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("package sample\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-m", "test policies")
	oldRepo, oldVersion := policyRepo, policyVersion
	t.Cleanup(func() { policyRepo, policyVersion = oldRepo, oldVersion })
	path := filepath.ToSlash(repo)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	policyRepo, policyVersion = "file://"+path, "feat/test-policy-source"
	if err := runPolicyUpdate(nil, nil); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(policy.DefaultPolicyDir(), "aliyun", "rules", "sample.rego")
	data, err := os.ReadFile(installed)
	if err != nil || strings.ReplaceAll(string(data), "\r\n", "\n") != "package sample\n" {
		t.Fatalf("installed=%q err=%v", data, err)
	}
	policyVersion = "missing-ref"
	if err := runPolicyUpdate(nil, nil); err == nil {
		t.Fatal("missing ref accepted")
	}
	if data, err := os.ReadFile(installed); err != nil || strings.ReplaceAll(string(data), "\r\n", "\n") != "package sample\n" {
		t.Fatalf("failed update changed installed policy: %q %v", data, err)
	}
}

func TestPolicyCleanConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	oldForce, oldStdin := cleanForce, os.Stdin
	t.Cleanup(func() { cleanForce, os.Stdin = oldForce, oldStdin })
	cleanForce = false
	for _, tc := range []struct {
		name, input string
		remove      bool
	}{{"cancel", "n\n", false}, {"end of input", "", false}, {"confirm", "yes\n", true}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(policy.DefaultPolicyDir(), "sample.rego")
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("package sample"), 0600); err != nil {
				t.Fatal(err)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.WriteString(tc.input); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			os.Stdin = reader
			defer func() { os.Stdin = oldStdin; reader.Close() }()
			if err := runPolicyClean(nil, nil); err != nil {
				t.Fatal(err)
			}
			_, err = os.Stat(path)
			if tc.remove && !os.IsNotExist(err) {
				t.Fatalf("policy still exists: %v", err)
			}
			if !tc.remove && err != nil {
				t.Fatalf("cancel removed policy: %v", err)
			}
		})
	}
}

func TestPolicyUpdateFromLocalArchive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	body := []byte("package sample\n")
	if err := tw.WriteHeader(&tar.Header{Name: "policies/rules/sample.rego", Mode: 0644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version.txt":
			_, _ = w.Write([]byte("1.2.3\n"))
		case "/1.2.3/infraguard-policies-1.2.3.tar.gz":
			_, _ = w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("INFRAGUARD_POLICY_BASE_URL", srv.URL)
	oldRepo, oldVersion := policyRepo, policyVersion
	t.Cleanup(func() { policyRepo, policyVersion = oldRepo, oldVersion })
	policyRepo, policyVersion = "", policy.DefaultPolicyVersion
	if err := runPolicyUpdate(nil, nil); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(policy.DefaultPolicyDir(), "rules", "sample.rego")
	data, err := os.ReadFile(installed)
	if err != nil || string(data) != "package sample\n" {
		t.Fatalf("installed=%q err=%v", data, err)
	}
}
