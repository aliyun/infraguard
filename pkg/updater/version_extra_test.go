package updater

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestVersionDiscoveryTransportErrors(t *testing.T) {
	u := New("1.0.0")
	u.baseURL = ":invalid"
	if _, err := u.GetLatestVersion(); err == nil {
		t.Fatal("invalid version URL accepted")
	}
	u.githubAPIURL = ":invalid"
	if _, err := u.GetSpecificVersion("1.0.0"); err == nil || !strings.Contains(err.Error(), "create request") {
		t.Fatalf("invalid release URL: %v", err)
	}
	u.baseURL, u.githubAPIURL = "http://example.invalid/", "http://example.invalid/releases"
	u.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection failed")
	})}
	if _, err := u.GetLatestVersion(); err == nil || !strings.Contains(err.Error(), "connection failed") {
		t.Fatalf("version transport error: %v", err)
	}
	if _, err := u.GetSpecificVersion("1.0.0"); err == nil || !strings.Contains(err.Error(), "connection failed") {
		t.Fatalf("release transport error: %v", err)
	}
	u.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingReader{}, Header: make(http.Header)}, nil
	})
	if _, err := u.GetLatestVersion(); err == nil || !strings.Contains(err.Error(), "failed to read latest version") {
		t.Fatalf("version body error: %v", err)
	}
}

func TestVersionDiscoveryFailureAndSelection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		body, wantErr string
	}{
		{"empty", 200, " \n", "empty"}, {"server error", 500, "bad", "500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			u := New("1.0.0")
			u.baseURL = srv.URL + "/"
			if _, err := u.GetLatestVersion(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name          string
		status        int
		body, wantErr string
	}{
		{"rate limited", 403, "", "rate limit"}, {"service failure", 500, "", "500"}, {"invalid JSON", 200, "not-json", "decode"}, {"no stable CLI", 200, `[{"tag_name":"v2.0.0","prerelease":true},{"tag_name":"vscode/v2.0.0"}]`, "no stable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			u := New("1.0.0")
			u.githubAPIURL = srv.URL
			if _, err := u.getLatestVersionFromGitHub(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error: %v", err)
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"tag_name":"vscode/v3.0.0"},{"tag_name":"v2.0.0","prerelease":true},{"tag_name":"cli/v1.5.0"}]`)
	}))
	defer srv.Close()
	u := New("1.0.0")
	u.githubAPIURL = srv.URL
	if got, err := u.getLatestVersionFromGitHub(); err != nil || got != "1.5.0" {
		t.Fatalf("latest %q: %v", got, err)
	}
	if got, err := u.GetSpecificVersion("v1.5.0"); err != nil || got.TagName != "cli/v1.5.0" {
		t.Fatalf("specific %+v: %v", got, err)
	}
	if _, err := u.GetSpecificVersion("9.9.9"); err == nil {
		t.Fatal("missing release accepted")
	}
	if _, err := New("invalid").NeedsUpdate("1.0.0"); err == nil {
		t.Fatal("invalid current version accepted")
	}
}

func TestGitHubAssetDiscoveryFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"release service error", "unavailable", "500", http.StatusInternalServerError},
		{"missing binary", `[{"tag_name":"cli/v1.2.3","prerelease":false,"assets":[{"name":"other"}]}]`, "no binary found", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			u := New("1.0.0")
			u.githubAPIURL = srv.URL
			if _, err := u.downloadGitHubAsset("1.2.3", "linux", "amd64"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	got := uniqueAssetNameCandidates([]string{"a", "b", "a", "b", "c"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("candidates=%v", got)
	}
}
