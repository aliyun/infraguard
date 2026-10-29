package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
)

func TestTableWaiverVisibility(t *testing.T) {
	results := []models.FileResult{{File: "template.yaml", Violations: []models.RichViolation{
		{ID: "active-rule", Severity: "high", Reason: "active reason", File: "template.yaml", Line: 3, Waiver: &models.WaiverInfo{Status: models.WaiverStatusActive, Source: "file", Reason: "approved", Expires: "2099-01-01"}},
		{ID: "expired-rule", Severity: "medium", Reason: "expired reason", File: "template.yaml", Line: 4, Snippet: "invalid: true", Waiver: &models.WaiverInfo{Status: models.WaiverStatusExpired, Source: "inline", Reason: "expired", Expires: "2000-01-01"}},
	}}}
	for _, tc := range []struct {
		name                                       string
		show, failExpired, wantActive, wantExpired bool
	}{
		{"default", false, true, false, true}, {"show waived", true, true, true, true}, {"suppress expired", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := New("table", &output, WithShowWaived(tc.show), WithFailOnExpired(tc.failExpired)).Render(results); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if got := strings.Contains(text, "active reason"); got != tc.wantActive {
				t.Errorf("active visible %v: %s", got, text)
			}
			if got := strings.Contains(text, "expired reason"); got != tc.wantExpired {
				t.Errorf("expired visible %v: %s", got, text)
			}
		})
	}
}

func TestTTYViolationRendering(t *testing.T) {
	var output bytes.Buffer
	r := New("table", &output)
	violations := []models.RichViolation{
		{ID: "rule-a", Severity: "high", Reason: "problem", File: "example.yaml", Line: 2, SnippetLines: []models.SnippetLine{{LineNum: 1, Content: "before"}, {LineNum: 2, Content: "problem", Highlight: true}}, Recommendation: "fix", Waiver: &models.WaiverInfo{Status: models.WaiverStatusExpired, Source: "file", Reason: "old", Expires: "2000-01-01"}},
		{ID: "rule-b", Severity: "low", Reason: "waived", Waiver: &models.WaiverInfo{Status: models.WaiverStatusActive, Source: "file", Reason: "accepted"}},
	}
	for i, v := range violations {
		r.renderViolationCard(i+1, v, true, i18n.Msg())
	}
	r.renderSummary(violations, true, i18n.Msg())
	r.renderWaiverNote(1, 1, true)
	r.renderWaiverNote(1, 0, true)
	for _, want := range []string{"rule-a", "rule-b", "before", "fix"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q in %s", want, output.String())
		}
	}
}
