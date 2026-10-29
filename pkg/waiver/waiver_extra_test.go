package waiver

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
)

func TestFindFileSearchesAncestorsAndSaveRoundTrip(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "project", "child")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	path := WorkspacePath(root)
	entries := []Waiver{{Rule: "needs-tag", Reason: "temporary", Expires: "2099-01-01"}}
	if err := Save(path, entries); err != nil {
		t.Fatal(err)
	}
	if got := FindFile(child); got != path {
		t.Fatalf("waiver file=%s want=%s", got, path)
	}
	loaded, err := Load(path)
	if err != nil || len(loaded.Waivers) != 1 || !reflect.DeepEqual(loaded.Waivers[0], entries[0]) {
		t.Fatalf("round trip=%+v err=%v", loaded, err)
	}
}

func TestFileWaiverGlobsRestrictScope(t *testing.T) {
	now := mustDate("2026-06-22")
	set := &Set{Waivers: []Waiver{{Rule: "needs-tag", Resource: "legacy-*", Files: []string{"**/legacy/*.tf"}, Reason: "approved", Owner: "team", Expires: "2026-12-31"}}}
	for _, tc := range []struct {
		name, file, resource string
		want                 bool
	}{
		{"matching path", filepath.Join(t.TempDir(), "legacy", "main.tf"), "legacy-db", true},
		{"different directory", filepath.Join(t.TempDir(), "prod", "main.tf"), "legacy-db", false},
		{"different resource", filepath.Join(t.TempDir(), "legacy", "main.tf"), "prod-db", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &models.RichViolation{ID: "rule:aliyun:needs-tag", ResourceID: tc.resource, File: tc.file}
			got := set.matchFile(v, now)
			if (got != nil) != tc.want {
				t.Fatalf("waiver=%+v", got)
			}
			if got != nil && (got.Source != "file" || got.Owner != "team" || got.Status != models.WaiverStatusActive) {
				t.Fatalf("waiver=%+v", got)
			}
		})
	}
}

func TestWaiverListAndLintStatuses(t *testing.T) {
	now := mustDate("2026-06-22")
	if got := (*Set)(nil).List(now); len(got) != 0 {
		t.Fatalf("nil list=%+v", got)
	}
	if got := (*Set)(nil).Lint(nil, now); len(got) != 0 {
		t.Fatalf("nil lint=%+v", got)
	}
	set := &Set{Waivers: []Waiver{
		{Rule: "active", Reason: "today", Expires: "2026-06-22"},
		{Rule: "expired", Reason: "past", Expires: "2026-06-21"},
		{Rule: "*", Reason: "permanent"},
		{Rule: "rule:aliyun:unknown", Reason: "bad date", Expires: "2026-02-30"},
	}}
	statuses := set.List(now)
	for i, want := range []string{"active", "expired", "permanent", "expired"} {
		if statuses[i].State != want || statuses[i].Waiver.Rule != set.Waivers[i].Rule {
			t.Errorf("status %d: %+v", i, statuses[i])
		}
	}
	issues := set.Lint(map[string]bool{"active": true, "expired": true}, now)
	counts := map[string]int{}
	for _, issue := range issues {
		counts[issue.Code]++
	}
	for _, code := range []string{CodeExpired, CodePermanent, CodeUnknownRule, CodeInvalidExpires} {
		if counts[code] != 1 {
			t.Errorf("issues %s=%d: %+v", code, counts[code], issues)
		}
	}
	if len(issues) != 4 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
}

func TestWaiverMatchingBoundariesAndSaveFailure(t *testing.T) {
	now := mustDate("2026-06-22")
	violation := &models.RichViolation{ID: "rule:aliyun:example", ResourceID: "db-1"}
	if (*Set)(nil).matchFile(violation, now) != nil {
		t.Fatal("nil set matched")
	}
	set := &Set{Waivers: []Waiver{{Rule: "other"}, {Rule: "example", Resource: "db-?"}}}
	if info := set.matchFile(violation, now); info == nil || info.Source != "file" {
		t.Fatalf("single character glob: %+v", info)
	}
	violation.ResourceID = "db-12"
	if set.matchFile(violation, now) != nil {
		t.Fatal("single character glob matched two characters")
	}
	if info := matchInline(violation, map[string][]Inline{"db-12": {{Rules: []string{"other"}}}}, now); info != nil {
		t.Fatalf("different inline rule matched: %+v", info)
	}
	if got := AttributeInline([]Inline{{Line: 1}}, nil); len(got) != 0 {
		t.Fatalf("directive without resources: %v", got)
	}
	if got := ShortRuleID("rule:invalid"); got != "rule:invalid" {
		t.Fatalf("invalid ID: %q", got)
	}
	root := t.TempDir()
	block := filepath.Join(root, "file")
	if err := os.WriteFile(block, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Save(filepath.Join(block, "waivers.yaml"), nil); err == nil {
		t.Fatal("save under file succeeded")
	}
}
