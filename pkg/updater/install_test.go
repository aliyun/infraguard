package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReplaceBinaryFilesAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		replace  func(string, string) error
		keepsOld bool
	}{{"unix", replaceUnixBinary, false}, {"windows", replaceWindowsBinary, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			current := filepath.Join(dir, "current")
			updated := filepath.Join(dir, "new")
			if err := os.WriteFile(current, []byte("old"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(updated, []byte("new"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := tc.replace(filepath.Join(dir, "missing"), current); err == nil {
				t.Fatal("missing update should fail")
			}
			data, err := os.ReadFile(current)
			if err != nil || string(data) != "old" {
				t.Fatalf("rollback: %q %v", data, err)
			}
			if err := tc.replace(updated, current); err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(current)
			if err != nil || string(data) != "new" {
				t.Fatalf("installation: %q %v", data, err)
			}
			if tc.keepsOld {
				data, err = os.ReadFile(current + ".old")
				if err != nil || string(data) != "old" {
					t.Fatalf("old binary: %q %v", data, err)
				}
				next := filepath.Join(dir, "next")
				if err := os.WriteFile(next, []byte("newer"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := tc.replace(next, current); err != nil {
					t.Fatal(err)
				}
				if data, err := os.ReadFile(current); err != nil || string(data) != "newer" {
					t.Fatalf("second update: %q %v", data, err)
				}
				data, err = os.ReadFile(current + ".old")
				if err != nil || string(data) != "new" {
					t.Fatalf("previous update backup: %q %v", data, err)
				}
			} else if _, err := os.Stat(current + ".backup"); !os.IsNotExist(err) {
				t.Fatalf("backup remains: %v", err)
			}
		})
	}
	if err := replaceUnixBinary("missing", filepath.Join(t.TempDir(), "missing-current")); err == nil {
		t.Fatal("missing current binary accepted")
	}
	if err := replaceWindowsBinary("missing", filepath.Join(t.TempDir(), "missing-current")); err == nil {
		t.Fatal("missing current binary accepted")
	}
}

func TestPrepareMacBinaryHandlesToolFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mock tools use POSIX shell scripts")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	for name, script := range map[string]string{
		"xattr":    "#!/bin/sh\nprintf 'xattr %s\\n' \"$*\" >> \"$MOCK_CALL_LOG\"\n[ \"$MOCK_XATTR_FAIL\" != 1 ]\n",
		"codesign": "#!/bin/sh\nprintf 'codesign %s\\n' \"$*\" >> \"$MOCK_CALL_LOG\"\n[ \"$MOCK_SIGN_FAIL\" != 1 ]\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("MOCK_CALL_LOG", logPath)
	t.Setenv("MOCK_XATTR_FAIL", "1")
	t.Setenv("MOCK_SIGN_FAIL", "0")
	if err := removeQuarantineAttributes(filepath.Join(dir, "binary")); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(log), "xattr -c ") || !strings.Contains(string(log), "xattr -d com.apple.quarantine ") || !strings.Contains(string(log), "codesign --force --deep --sign - ") {
		t.Fatalf("tool invocations %q: %v", log, err)
	}
	t.Setenv("MOCK_SIGN_FAIL", "1")
	if err := removeQuarantineAttributes(filepath.Join(dir, "binary")); err == nil || !strings.Contains(err.Error(), "failed to re-sign") {
		t.Fatalf("expected signing error, got %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("broken stream") }
func (failingReader) Close() error             { return nil }

func TestDownloadErrorsAndProgress(t *testing.T) {
	u := New("1.0.0")
	var calls int
	u.SetProgressFunc(func(current, total int64) {
		calls++
		if current != 3 || total != 3 {
			t.Errorf("progress %d/%d", current, total)
		}
	})
	path, err := u.downloadRawAsset(&http.Response{Body: io.NopCloser(strings.NewReader("abc")), ContentLength: 3}, &Asset{Name: "infraguard"})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "abc" || calls != 1 {
		t.Fatalf("download: %q calls %d: %v", data, calls, err)
	}
	if _, err := u.downloadRawAsset(&http.Response{Body: failingReader{}}, &Asset{Name: "infraguard"}); err == nil {
		t.Fatal("broken raw stream accepted")
	}
	if _, err := u.downloadArchiveAsset(&http.Response{Body: failingReader{}}, &Asset{Name: "infraguard.tar.gz"}); err == nil {
		t.Fatal("broken archive stream accepted")
	}
	if _, err := u.downloadAsset(&Asset{BrowserDownloadURL: ":bad"}); err == nil {
		t.Fatal("invalid URL accepted")
	}
	if isFallbackHTTPError(errors.New("other")) || !isFallbackHTTPError(httpStatusError{StatusCode: 404}) || isFallbackHTTPError(httpStatusError{StatusCode: 500}) {
		t.Fatal("HTTP fallback classification")
	}
}

func TestInstallStopsOnDownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer srv.Close()
	u := New("1.0.0")
	u.baseURL = srv.URL + "/"
	if err := u.DownloadAndInstall("1.1.0"); err == nil || !strings.Contains(err.Error(), "download failed") {
		t.Fatalf("expected download error, got %v", err)
	}
}

func TestExtractBinaryRejectsInvalidArchives(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := extractBinaryFromArchive(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing archive accepted")
	}
	if _, err := extractBinaryFromArchive(write("invalid.gz", []byte("not gzip"))); err == nil {
		t.Fatal("invalid gzip accepted")
	}
	if _, err := extractBinaryFromArchive(write("no-binary.tar.gz", buildUpdaterTarGz(t, map[string]string{"README": "not a binary"}))); err == nil {
		t.Fatal("archive without binary accepted")
	}
	for _, tc := range []struct {
		name string
		size int64
		body string
	}{
		{"oversized", maxArchiveEntrySize + 1, ""},
		{"truncated", 10, "short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&tar.Header{Name: "infraguard", Mode: 0755, Size: tc.size}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := extractBinaryFromArchive(write(tc.name+".tar.gz", buf.Bytes())); err == nil {
				t.Fatal("invalid binary accepted")
			}
		})
	}
}
