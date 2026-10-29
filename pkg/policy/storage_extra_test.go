package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
)

func TestLoadProviderRulesPacksAndLibraries(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"aliyun/rules/one.rego": `package infraguard.rules.aliyun.one
import rego.v1
rule_meta := {"name": "Rule", "severity": "low"}`,
		"aliyun/packs/default.rego": `package infraguard.packs.aliyun.default
import rego.v1
pack_meta := {"name": "Pack", "rules": ["one"]}`,
		"aliyun/lib/helpers.rego": "package helpers\nanswer := 42\n",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	loader := &Loader{policyDir: root, index: &models.PolicyIndex{Rules: map[string]*models.Rule{}, Packs: map[string]*models.Pack{}}}
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}
	if len(loader.GetAllRules()) != 1 || loader.GetAllRules()[0].ID != "rule:aliyun:one" || len(loader.GetAllPacks()) != 1 || loader.GetAllPacks()[0].ID != "pack:aliyun:default" {
		t.Fatalf("loaded rules and packs: %+v %+v", loader.GetAllRules(), loader.GetAllPacks())
	}
	helperPath := filepath.Join(root, "aliyun", "lib", "helpers.rego")
	if loader.GetLibModules()[helperPath] != files["aliyun/lib/helpers.rego"] {
		t.Fatalf("library modules: %+v", loader.GetLibModules())
	}
	loader.policyDir = filepath.Join(root, "missing")
	if err := loader.Load(); err == nil {
		t.Fatal("missing policy directory accepted")
	}
}

func TestPolicyArchiveRejectsOversizedAndTruncatedFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int64
		body string
	}{
		{"oversized", maxPolicyArchiveEntry + 1, ""},
		{"truncated", 10, "short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			gz := gzip.NewWriter(&data)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&tar.Header{Name: "policies/rule.rego", Mode: 0644, Size: tc.size}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			archive := filepath.Join(root, "policy.tar.gz")
			if err := os.WriteFile(archive, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := extractPolicyArchive(archive, filepath.Join(root, "extract")); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
}

func TestPolicyDirectoryCopyAndReplacement(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	dest := filepath.Join(root, "dest")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "rule.rego"), []byte("package example"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(source, dest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "nested", "rule.rego"))
	if err != nil || string(data) != "package example" {
		t.Fatalf("copied content: %q %v", data, err)
	}
	if err := copyDir(filepath.Join(root, "missing"), filepath.Join(root, "other")); err == nil {
		t.Fatal("copy of missing directory succeeded")
	}
	if err := ValidatePath(dest); err != nil {
		t.Fatal(err)
	}
	files, err := DiscoverRegoFiles(dest)
	if err != nil || len(files) != 1 {
		t.Fatalf("discovery: %v %v", files, err)
	}
	if err := replacePolicyDir(filepath.Join(root, "missing"), dest); err == nil {
		t.Fatal("missing replacement accepted")
	}
	if _, err := os.Stat(filepath.Join(dest, "nested", "rule.rego")); err != nil {
		t.Fatalf("existing directory lost after failed replacement: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "rule.rego"), []byte("package updated"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := replacePolicyDir(source, dest); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dest, "nested", "rule.rego"))
	if err != nil || string(data) != "package updated" {
		t.Fatalf("replacement: %q %v", data, err)
	}
	if _, err := os.Stat(dest + ".old"); !os.IsNotExist(err) {
		t.Fatalf("backup remains: %v", err)
	}
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePath(empty); err == nil {
		t.Fatal("empty directory accepted")
	}
	invalid := filepath.Join(empty, "readme.txt")
	if err := os.WriteFile(invalid, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePath(invalid); err == nil {
		t.Fatal("non-Rego file accepted")
	}
	if _, err := DiscoverRegoFiles(invalid); err == nil {
		t.Fatal("non-Rego file discovered")
	}
}

func TestResolvePolicyVersionHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
		fail       bool
	}{
		{"valid", " v1.2.3\n", 200, "1.2.3", false}, {"empty", "  ", 200, "", true}, {"missing", "not found", 404, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/version.txt" {
					t.Errorf("path %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			t.Setenv(policyBaseURLEnv, srv.URL)
			got, err := resolvePolicyVersion("")
			if (err != nil) != tc.fail || got != tc.want {
				t.Fatalf("version %q error %v", got, err)
			}
			if tc.status == 404 && (err == nil || !strings.Contains(err.Error(), "404")) {
				t.Fatalf("status error: %v", err)
			}
		})
	}
	if got, err := resolvePolicyVersion("v2.0.0"); err != nil || got != "2.0.0" {
		t.Fatalf("explicit version %q: %v", got, err)
	}
}

func TestLatestPolicyUpdateFallsBackToLocalGit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_COUNT", "0")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	repo := initPolicyGitRepo(t, "cli/v1.0.0", map[string]string{"policies/aliyun/rules/local.rego": "package infraguard.rules.aliyun.local\n"})
	t.Cleanup(func() { _ = os.RemoveAll(repo) })
	path := filepath.ToSlash(repo)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	t.Setenv("INFRAGUARD_POLICY_GITHUB_REPO", "file://"+path)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("INFRAGUARD_POLICY_BASE_URL", srv.URL)
	dest := filepath.Join(home, "policies")
	if err := NewManager(dest).UpdateFromOSS(""); err != nil {
		t.Fatalf("local git fallback: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "aliyun", "rules", "local.rego"))
	if err != nil || !strings.Contains(string(data), "infraguard.rules.aliyun.local") {
		t.Fatalf("fallback content: %q %v", data, err)
	}
}

func TestPolicyUpdateErrorsKeepExistingFiles(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		status        int
		body          string
	}{
		{"version service failure", "", http.StatusInternalServerError, "unavailable"},
		{"invalid archive", "1.0.0", http.StatusOK, "not gzip"},
		{"empty archive", "1.0.0", http.StatusOK, string(buildPolicyTarGz(t, nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			t.Setenv("INFRAGUARD_POLICY_BASE_URL", srv.URL)
			dest := filepath.Join(t.TempDir(), "policies")
			if err := os.MkdirAll(dest, 0755); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(dest, "old.rego")
			if err := os.WriteFile(old, []byte("package old"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := NewManager(dest).UpdateFromOSS(tc.version); err == nil {
				t.Fatal("failed update succeeded")
			}
			data, err := os.ReadFile(old)
			if err != nil || string(data) != "package old" {
				t.Fatalf("existing policy changed: %q %v", data, err)
			}
		})
	}
}

func TestPolicyUpdateFailsWhenDestinationParentIsFile(t *testing.T) {
	archive := buildPolicyTarGz(t, map[string]string{"policies/rules/example.rego": "package example"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer srv.Close()
	t.Setenv("INFRAGUARD_POLICY_BASE_URL", srv.URL)
	parent := filepath.Join(t.TempDir(), "existing-file")
	if err := os.WriteFile(parent, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := NewManager(filepath.Join(parent, "policies")).UpdateFromOSS("1.0.0"); err == nil {
		t.Fatal("update through a file succeeded")
	}
	if data, err := os.ReadFile(parent); err != nil || string(data) != "keep" {
		t.Fatalf("existing file changed: %q %v", data, err)
	}
}

func TestExtractPolicyArchiveRejectsUnsafeEntries(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "policy.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	entries := []struct {
		name, body string
		kind       byte
		link       string
	}{
		{"policies/", "", tar.TypeDir, ""},
		{"policies/ok.rego", "package ok", tar.TypeReg, ""},
		{"../escape.rego", "escape", tar.TypeReg, ""},
		{"/absolute.rego", "absolute", tar.TypeReg, ""},
		{"C:/drive.rego", "drive", tar.TypeReg, ""},
		{"policies/link", "", tar.TypeSymlink, "../../escape.rego"},
	}
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0644, Typeflag: e.kind, Linkname: e.link, Size: int64(len(e.body))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "output")
	if err := extractPolicyArchive(archive, dst); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dst, "policies", "ok.rego"))
	if err != nil || string(data) != "package ok" {
		t.Fatalf("valid file: %q %v", data, err)
	}
	for _, name := range []string{filepath.Join(root, "escape.rego"), filepath.Join(dst, "absolute.rego"), filepath.Join(dst, "policies", "link")} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Errorf("unsafe entry %s exists: %v", name, err)
		}
	}
	if err := extractPolicyArchive(filepath.Join(root, "missing"), dst); err == nil {
		t.Fatal("missing archive accepted")
	}
	invalid := filepath.Join(root, "invalid.gz")
	if err := os.WriteFile(invalid, []byte("not gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := extractPolicyArchive(invalid, dst); err == nil {
		t.Fatal("invalid archive accepted")
	}
}

func TestArchiveRootDir(t *testing.T) {
	root := t.TempDir()
	if _, err := archiveRootDir(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
	if _, err := archiveRootDir(root); err == nil {
		t.Fatal("empty archive accepted")
	}
	inner := filepath.Join(root, "policies")
	if err := os.Mkdir(inner, 0755); err != nil {
		t.Fatal(err)
	}
	if got, err := archiveRootDir(root); err != nil || got != inner {
		t.Fatalf("single directory: %q %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest"), []byte("metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := archiveRootDir(root); err != nil || got != root {
		t.Fatalf("multiple entries: %q %v", got, err)
	}
}

func TestSortPolicyArraysPreservesAssociatedComments(t *testing.T) {
	input := `meta := {
  "rules": ["rule:z", "rule:a"],
  "resource_types": [
    # explanation for Z
    "Z",
    # disabled A
    # "A",
    # explanation for B
    "B"
    # trailing comment
  ],
  "other": ["z", "a"]
}`
	got := string(sortArrayElements([]byte(input)))
	expected := `meta := {
  "rules": ["rule:a", "rule:z"],
  "resource_types": [
    # disabled A
    # "A",
    # explanation for B
    "B",
    # explanation for Z
    "Z"
    # trailing comment
  ],
  "other": ["z", "a"]
}`
	if got != expected {
		t.Fatalf("sorted array:\n%s\nwant:\n%s", got, expected)
	}
	if again := string(sortArrayElements([]byte(got))); again != got {
		t.Fatalf("format not idempotent:\n%s", again)
	}
}

func TestSortTranslationLanguagesKeepsCommentsAndUnknownLanguages(t *testing.T) {
	input := `"name": {
    # Swedish translation
    "sv": "Hej",
    # Chinese translation
    "zh": "你好",
    # Xhosa translation
    "xh": "Molo",
    # English translation
    "en": "Hello"
    # final note
}`
	got := string(sortI18nLanguages([]byte(input)))
	expected := "\"name\": {\n\t# English translation\n\t\"en\": \"Hello\",\n\t# Chinese translation\n\t\"zh\": \"你好\",\n\t# Swedish translation\n\t\"sv\": \"Hej\",\n\t# Xhosa translation\n\t\"xh\": \"Molo\"\n\t# final note\n}"
	// Comments retain their original indentation while entries use formatter indentation.
	expected = strings.ReplaceAll(expected, "\t#", "    #")
	if got != expected {
		t.Fatalf("sorted translations:\n%s\nwant:\n%s", got, expected)
	}
	if again := string(sortI18nLanguages([]byte(got))); again != got {
		t.Fatalf("format not idempotent:\n%s", again)
	}
}

func TestFormatDirectoryReportsMixedResults(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	unchanged := write("valid.rego", "package example\n")
	changed := write("nested/unformatted.rego", "package example\n\nallow:=true\n")
	invalid := write("invalid.rego", "package ???\n")
	write("ignored.txt", "not a policy")
	summary, err := FormatDirectory(dir, false)
	if err != nil || summary.TotalFiles != 3 || summary.ChangedFiles != 1 || summary.UnchangedFiles != 1 || summary.ErrorFiles != 1 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	byFile := map[string]*FormatResult{}
	for _, r := range summary.Results {
		byFile[r.FilePath] = r
	}
	if byFile[unchanged].Changed || !byFile[changed].Changed || byFile[invalid].Error == nil {
		t.Fatalf("results: %+v", byFile)
	}
	single, err := FormatPath(invalid, false)
	if err != nil || single.TotalFiles != 1 || single.ErrorFiles != 1 {
		t.Fatalf("invalid file: %+v %v", single, err)
	}
	if _, err := FormatDirectory(filepath.Join(dir, "missing"), false); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestPolicyUpdatePreservesExistingOnServerOrArchiveFailure(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
	}{
		{"server failure", "unavailable", http.StatusInternalServerError},
		{"corrupt archive", "not a gzip archive", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dest := filepath.Join(root, "installed")
			if err := os.Mkdir(dest, 0755); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(dest, "old.rego")
			if err := os.WriteFile(old, []byte("package old"), 0600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code); fmt.Fprint(w, tc.body) }))
			defer server.Close()
			t.Setenv(policyBaseURLEnv, server.URL)
			if err := NewManager(dest).UpdateFromOSS("1.2.3"); err == nil {
				t.Fatal("invalid update succeeded")
			}
			data, err := os.ReadFile(old)
			if err != nil || string(data) != "package old" {
				t.Fatalf("existing policy changed: %q %v", data, err)
			}
		})
	}
}

func TestPolicyStorageFailuresPreserveExistingData(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "rule.rego"), []byte("package rule"), 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "dest")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "nested"), []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(source, dest); err == nil {
		t.Fatal("copy through a file accepted")
	}
	if err := replacePolicyDir(source, filepath.Join(dest, "nested", "policies")); err == nil {
		t.Fatal("replacement through a file accepted")
	}
	if data, err := os.ReadFile(filepath.Join(source, "nested", "rule.rego")); err != nil || string(data) != "package rule" {
		t.Fatalf("source changed: %q %v", data, err)
	}
}

func TestCopyPolicyDirectoryReportsFileConflicts(t *testing.T) {
	t.Run("destination is directory", func(t *testing.T) {
		root := t.TempDir()
		source, dest := filepath.Join(root, "source"), filepath.Join(root, "dest")
		if err := os.MkdirAll(source, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "rule.rego"), []byte("package rule"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dest, "rule.rego"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := copyDir(source, dest); err == nil {
			t.Fatal("file overwrote a destination directory")
		}
		if info, err := os.Stat(filepath.Join(dest, "rule.rego")); err != nil || !info.IsDir() {
			t.Fatalf("destination directory changed: %v", err)
		}
	})
	t.Run("broken source link", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		if err := os.MkdirAll(source, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(source, "broken.rego")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := copyDir(source, filepath.Join(root, "dest")); err == nil {
			t.Fatal("broken source link accepted")
		}
	})
}

func TestDownloadPolicyFileFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/error":
			http.Error(w, "unavailable", http.StatusInternalServerError)
		case "/truncated":
			w.Header().Set("Content-Length", "100")
			fmt.Fprint(w, "short")
		default:
			fmt.Fprint(w, "valid")
		}
	}))
	defer srv.Close()
	for _, tc := range []struct{ name, url, dest string }{
		{"bad URL", ":bad", filepath.Join(t.TempDir(), "out")}, {"server failure", srv.URL + "/error", filepath.Join(t.TempDir(), "out")},
		{"truncated", srv.URL + "/truncated", filepath.Join(t.TempDir(), "out")}, {"invalid destination", srv.URL + "/valid", filepath.Join(t.TempDir(), "missing", "out")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := downloadFile(tc.url, tc.dest); err == nil {
				t.Fatal("download failure accepted")
			}
		})
	}
}

func TestPolicyDirectoryAndGitRefFallbacks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	override := filepath.Join(home, "custom")
	t.Setenv("INFRAGUARD_POLICY_DIR", override)
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", override)
	if DefaultPolicyDir() != override || WorkspacePolicyDir() != override {
		t.Fatal("directory override ignored")
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if got := DefaultPolicyDir(); got != ".infraguard/policies" {
		t.Fatalf("missing home fallback=%q", got)
	}
	for _, tc := range []struct {
		version string
		want    []string
	}{
		{"", []string{"main"}}, {"latest", []string{"main"}}, {"feat/example", []string{"feat/example"}},
		{"1.2.3", []string{"1.2.3", "v1.2.3", "cli/v1.2.3"}}, {"v1.2.3", []string{"v1.2.3", "1.2.3", "cli/v1.2.3"}},
	} {
		if got := policyGitRefCandidates(tc.version); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("refs %q=%v want %v", tc.version, got, tc.want)
		}
	}
	for _, tc := range []struct {
		err  error
		want bool
	}{{nil, false}, {httpStatusError{StatusCode: 404}, true}, {fmt.Errorf("wrapped: %w", httpStatusError{StatusCode: 403}), true}, {httpStatusError{StatusCode: 500}, false}} {
		if got := isFallbackHTTPError(tc.err); got != tc.want {
			t.Errorf("fallback(%v)=%v", tc.err, got)
		}
	}
}

func TestSanitizePolicyArchivePaths(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		invalid     bool
	}{
		{"", "", true}, {"a\x00b", "", true}, {"../escape", "", true}, {"..\\escape", "", true},
		{"/absolute", "", true}, {"C:/absolute", "", true}, {"././", "", false},
		{"./rules/one.rego", "rules/one.rego", false}, {"rules\\one.rego", "rules/one.rego", false},
	} {
		got, err := sanitizeArchivePath(tc.input)
		if (err != nil) != tc.invalid || got != tc.want {
			t.Errorf("path %q: got=%q err=%v", tc.input, got, err)
		}
	}
}

func TestLoadFlatProviderRulesPacksAndLibraries(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"vendor/one.rego": `package infraguard.rules.vendor.one
import rego.v1
rule_meta := {"name": "Rule", "severity": "low"}`,
		"vendor/pack.rego": `package infraguard.packs.vendor.default
import rego.v1
pack_meta := {"name": "Pack", "rules": ["one"]}`,
		"vendor/lib/helpers.rego": "package helpers\nanswer := 42\n",
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	loader := &Loader{policyDir: root, index: &models.PolicyIndex{Rules: map[string]*models.Rule{}, Packs: map[string]*models.Pack{}}}
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}
	if len(loader.GetAllRules()) != 1 || len(loader.GetAllPacks()) != 1 {
		t.Fatalf("flat policy discovery: %d rules, %d packs", len(loader.GetAllRules()), len(loader.GetAllPacks()))
	}
	if loader.GetLibModules()[filepath.Join(root, "vendor", "lib", "helpers.rego")] == "" {
		t.Fatal("flat provider library not loaded")
	}
}

func TestPolicyArchiveDefaultsPermissionsAndReportsBlockedPaths(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "policies.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range []*tar.Header{{Name: "nested/", Typeflag: tar.TypeDir, Mode: 0755}, {Name: "nested/rule.rego", Typeflag: tar.TypeReg, Mode: 0, Size: 7}} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("package")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "out")
	if err := extractPolicyArchive(archive, dst); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dst, "nested", "rule.rego"))
	if err != nil || info.Mode().Perm()&0600 != 0600 {
		t.Fatalf("default permissions: %v %v", info, err)
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocked, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := extractPolicyArchive(archive, blocked); err == nil {
		t.Fatal("destination file accepted as directory")
	}
	nestedBlocked := filepath.Join(root, "nested-blocked")
	if err := os.Mkdir(nestedBlocked, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedBlocked, "nested"), []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := extractPolicyArchive(archive, nestedBlocked); err == nil {
		t.Fatal("archive directory created over file")
	}
}
