package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
)

func TestUpdateCommandVersionAndDownloadErrors(t *testing.T) {
	oldCheck, oldForce, oldTarget, oldVersion := checkOnly, forceUpdate, targetVersion, Version
	t.Cleanup(func() { checkOnly, forceUpdate, targetVersion, Version = oldCheck, oldForce, oldTarget, oldVersion })
	Version = "1.2.3"
	forceUpdate = false
	checkOnly = true
	for _, version := range []string{"1.2.3", "1.2.4", "1.2.2"} {
		targetVersion = version
		if err := runUpdate(nil, nil); err != nil {
			t.Errorf("check %s: %v", version, err)
		}
	}
	targetVersion = "not-a-version"
	if err := runUpdate(nil, nil); err == nil {
		t.Fatal("invalid version accepted")
	}
	targetVersion, checkOnly = "1.2.3", false
	if err := runUpdate(nil, nil); err == nil {
		t.Fatal("same version update accepted without force")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("INFRAGUARD_UPDATE_BASE_URL", srv.URL)
	targetVersion, checkOnly = "2.0.0", false
	if err := runUpdate(nil, nil); err == nil || !strings.Contains(strings.ToLower(err.Error()), "fail") {
		t.Fatalf("download failure expected: %v", err)
	}
}

func TestUpdateChecksLatestAndReportsRateLimit(t *testing.T) {
	oldCheck, oldForce, oldTarget, oldVersion := checkOnly, forceUpdate, targetVersion, Version
	t.Cleanup(func() { checkOnly, forceUpdate, targetVersion, Version = oldCheck, oldForce, oldTarget, oldVersion })
	versionFailure := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version.txt":
			if versionFailure {
				http.Error(w, "unavailable", http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "v1.3.0\n")
		case "/releases":
			http.Error(w, "rate limit", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("INFRAGUARD_UPDATE_BASE_URL", srv.URL)
	t.Setenv("INFRAGUARD_GITHUB_API_URL", srv.URL+"/releases")
	Version, targetVersion, forceUpdate, checkOnly = "1.2.3", "", false, true
	if err := runUpdate(nil, nil); err != nil {
		t.Fatalf("latest check: %v", err)
	}
	versionFailure = true
	if err := runUpdate(nil, nil); err == nil {
		t.Fatal("failed latest version fetch accepted")
	}
	targetVersion, checkOnly = "2.0.0", false
	if err := runUpdate(nil, nil); err == nil || err.Error() != i18n.Msg().Update.Errors.RateLimit {
		t.Fatalf("rate limit error: %v", err)
	}
}
