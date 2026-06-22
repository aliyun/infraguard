package waiver

import (
	"time"
)

// Issue severity levels for lint findings.
const (
	IssueError   = "error"
	IssueWarning = "warning"
)

// Issue codes (localized by the caller).
const (
	CodeMissingRule    = "missing_rule"
	CodeMissingReason  = "missing_reason"
	CodeUnknownRule    = "unknown_rule"
	CodeInvalidExpires = "invalid_expires"
	CodeExpired        = "expired"
	CodePermanent      = "permanent"
)

// Issue is a problem found while linting a waiver set.
type Issue struct {
	Index    int    // Index of the waiver in the file (0-based)
	Rule     string // Rule the waiver targets
	Severity string // error | warning
	Code     string // One of the Code* constants
	Detail   string // Extra context (e.g. the rule name or date), may be empty
}

// Lint validates a waiver set. knownRules is the set of valid short rule IDs; pass
// nil to skip the unknown-rule check. now is used to detect expired waivers.
func (s *Set) Lint(knownRules map[string]bool, now time.Time) []Issue {
	var issues []Issue
	if s == nil {
		return issues
	}
	for i, w := range s.Waivers {
		add := func(sev, code, detail string) {
			issues = append(issues, Issue{Index: i, Rule: w.Rule, Severity: sev, Code: code, Detail: detail})
		}

		if w.Rule == "" {
			add(IssueError, CodeMissingRule, "")
		}
		if w.Reason == "" {
			add(IssueError, CodeMissingReason, "")
		}
		if w.Rule != "" && w.Rule != "*" && knownRules != nil {
			if !knownRules[ShortRuleID(w.Rule)] {
				add(IssueWarning, CodeUnknownRule, w.Rule)
			}
		}
		if w.Expires != "" {
			t, err := time.Parse(dateLayout, w.Expires)
			if err != nil {
				add(IssueError, CodeInvalidExpires, w.Expires)
			} else if now.Truncate(24 * time.Hour).After(t) {
				add(IssueWarning, CodeExpired, w.Expires)
			}
		} else {
			add(IssueWarning, CodePermanent, "")
		}
	}
	return issues
}

// Status summarizes a single waiver for listing.
type Status struct {
	Waiver  Waiver
	State   string // active | expired | permanent
	Expires string
}

// List returns per-waiver status for display.
func (s *Set) List(now time.Time) []Status {
	var out []Status
	if s == nil {
		return out
	}
	for _, w := range s.Waivers {
		state := "active"
		switch {
		case w.Expires == "":
			state = "permanent"
		case statusFor(w.Expires, now) == "expired":
			state = "expired"
		}
		out = append(out, Status{Waiver: w, State: state, Expires: w.Expires})
	}
	return out
}
