package waiver

import (
	"testing"
	"time"

	"github.com/aliyun/infraguard/pkg/models"
)

func mustDate(s string) time.Time {
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestStatusFor(t *testing.T) {
	now := mustDate("2026-06-22")
	cases := []struct {
		expires string
		want    string
	}{
		{"", models.WaiverStatusActive},           // permanent
		{"2026-12-31", models.WaiverStatusActive}, // future
		{"2026-06-22", models.WaiverStatusActive}, // today (inclusive)
		{"2025-01-01", models.WaiverStatusExpired},
		{"not-a-date", models.WaiverStatusExpired},
	}
	for _, c := range cases {
		if got := statusFor(c.expires, now); got != c.want {
			t.Errorf("statusFor(%q) = %q, want %q", c.expires, got, c.want)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"legacy-*", "legacy-bucket", true},
		{"legacy-*", "prod-bucket", false},
		{"*", "anything", true},
		{"envs/legacy/**", "envs/legacy/db/main.tf", true},
		{"envs/legacy/**", "envs/prod/main.tf", false},
		{"**/main.tf", "a/b/c/main.tf", true},
		{"a/*/c", "a/b/c", true},
		{"a/*/c", "a/b/d/c", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestParseInline(t *testing.T) {
	content := `Resources:
  # infraguard:ignore=rule-a,rule-b reason="legacy" expires=2026-12-31
  Foo:
    Type: X
  Bar:
    Type: Y  // infraguard:ignore=rule-c reason="tf style"
`
	inlines := ParseInline("main.tf", content)
	if len(inlines) != 2 {
		t.Fatalf("got %d inlines, want 2: %+v", len(inlines), inlines)
	}
	if inlines[0].Line != 2 || len(inlines[0].Rules) != 2 || inlines[0].Reason != "legacy" || inlines[0].Expires != "2026-12-31" {
		t.Errorf("inline[0] unexpected: %+v", inlines[0])
	}
	if inlines[1].Rules[0] != "rule-c" || inlines[1].Reason != "tf style" {
		t.Errorf("inline[1] unexpected: %+v", inlines[1])
	}
}

func TestAttributeInline(t *testing.T) {
	// Directive on line 2 is a head comment for resource Foo (starts line 3).
	// Directive on line 6 is inside resource Bar's block (starts line 5).
	inlines := []Inline{
		{Line: 2, Rules: []string{"r1"}},
		{Line: 6, Rules: []string{"r2"}},
	}
	resources := []ResourceLine{
		{ID: "Foo", Line: 3},
		{ID: "Bar", Line: 5},
	}
	got := AttributeInline(inlines, resources)
	if len(got["Foo"]) != 1 || got["Foo"][0].Rules[0] != "r1" {
		t.Errorf("Foo attribution wrong: %+v", got["Foo"])
	}
	if len(got["Bar"]) != 1 || got["Bar"][0].Rules[0] != "r2" {
		t.Errorf("Bar attribution wrong: %+v", got["Bar"])
	}
}

func TestAnnotateFileWaiver(t *testing.T) {
	now := mustDate("2026-06-22")
	set := &Set{Waivers: []Waiver{
		{Rule: "needs-tag", Resource: "Active*", Reason: "ok", Expires: "2026-12-31"},
		{Rule: "needs-tag", Resource: "Expired", Reason: "old", Expires: "2025-01-01"},
	}}
	results := []models.FileResult{{
		File: "t.yaml",
		Violations: []models.RichViolation{
			{ID: "rule:aliyun:needs-tag", ResourceID: "ActiveBucket"},
			{ID: "rule:aliyun:needs-tag", ResourceID: "Expired"},
			{ID: "rule:aliyun:needs-tag", ResourceID: "Unmatched"},
		},
	}}

	set.Annotate(results, nil, now)

	v := results[0].Violations
	if v[0].Waiver == nil || v[0].Waiver.Status != models.WaiverStatusActive {
		t.Errorf("ActiveBucket should be active-waived: %+v", v[0].Waiver)
	}
	if v[1].Waiver == nil || v[1].Waiver.Status != models.WaiverStatusExpired {
		t.Errorf("Expired should be expired-waived: %+v", v[1].Waiver)
	}
	if v[2].Waiver != nil {
		t.Errorf("Unmatched should have no waiver: %+v", v[2].Waiver)
	}
}

func TestAnnotateInlinePrecedence(t *testing.T) {
	now := mustDate("2026-06-22")
	// File waiver would match, but an inline directive should take precedence.
	set := &Set{Waivers: []Waiver{
		{Rule: "needs-tag", Resource: "Foo", Reason: "file-level", Expires: "2026-12-31"},
	}}
	results := []models.FileResult{{
		File:       "t.yaml",
		Violations: []models.RichViolation{{ID: "needs-tag", ResourceID: "Foo"}},
	}}
	inlineByFile := map[string]map[string][]Inline{
		"t.yaml": {"Foo": {{Rules: []string{"needs-tag"}, Reason: "inline-level"}}},
	}
	set.Annotate(results, inlineByFile, now)

	w := results[0].Violations[0].Waiver
	if w == nil || w.Source != "inline" || w.Reason != "inline-level" {
		t.Errorf("expected inline waiver to win, got %+v", w)
	}
}

func TestLint(t *testing.T) {
	now := mustDate("2026-06-22")
	set := &Set{Waivers: []Waiver{
		{Rule: "known", Reason: "ok", Expires: "2026-12-31"}, // clean
		{Rule: "", Reason: ""},                               // missing rule + reason + permanent
		{Rule: "ghost", Reason: "x", Expires: "2025-01-01"},  // unknown + expired
	}}
	known := map[string]bool{"known": true}
	issues := set.Lint(known, now)

	errs, warns := 0, 0
	for _, i := range issues {
		if i.Severity == IssueError {
			errs++
		} else {
			warns++
		}
	}
	if errs < 2 {
		t.Errorf("expected >=2 errors (missing rule, missing reason), got %d: %+v", errs, issues)
	}
	if warns < 2 {
		t.Errorf("expected >=2 warnings (unknown rule, expired), got %d: %+v", warns, issues)
	}
}
