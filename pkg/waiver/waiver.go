// Package waiver implements rule waivers (suppressions) for InfraGuard scans.
//
// Two sources of waivers are supported:
//   - A central waiver file (.infraguard/waivers.yaml) committed to the repo.
//   - Inline comments in templates, e.g. "# infraguard:ignore=<rule-id> reason=..."
//
// A waiver never deletes a finding silently: matched violations are annotated with
// a *models.WaiverInfo so reporters and exit-code logic can treat them explicitly.
// Expired waivers are reported as expired and (by caller policy) still fail the build.
package waiver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aliyun/infraguard/pkg/models"
	"gopkg.in/yaml.v3"
)

// DefaultRelPath is the conventional workspace location of the waiver file.
const DefaultRelPath = ".infraguard/waivers.yaml"

// dateLayout is the accepted format for the "expires" field.
const dateLayout = "2006-01-02"

// Waiver is a single entry in the central waiver file.
type Waiver struct {
	Rule     string   `yaml:"rule"`               // Short rule ID, or "*" for all rules
	Resource string   `yaml:"resource,omitempty"` // Resource ID glob; empty matches any resource
	Files    []string `yaml:"files,omitempty"`    // File path globs; empty matches any file
	Reason   string   `yaml:"reason"`             // Required justification
	Expires  string   `yaml:"expires,omitempty"`  // YYYY-MM-DD; empty means permanent
	Owner    string   `yaml:"owner,omitempty"`    // Responsible person
}

// fileDoc is the on-disk structure of the waiver file.
type fileDoc struct {
	Version int      `yaml:"version"`
	Waivers []Waiver `yaml:"waivers"`
}

// Set is a loaded collection of central-file waivers.
type Set struct {
	Path    string
	Waivers []Waiver
}

// Inline is a parsed inline-comment directive with its source line.
type Inline struct {
	File    string
	Line    int
	Rules   []string // short rule IDs, or ["*"]
	Reason  string
	Expires string
}

// directiveRe matches "infraguard:ignore=<rules> ..." anywhere in a comment line.
var directiveRe = regexp.MustCompile(`infraguard:ignore=([^\s]+)(.*)`)

// kvReason and kvExpires extract reason="..." / expires=... from the directive tail.
var (
	reasonRe  = regexp.MustCompile(`reason\s*=\s*"([^"]*)"`)
	expiresRe = regexp.MustCompile(`expires\s*=\s*([0-9]{4}-[0-9]{2}-[0-9]{2})`)
)

// FindFile locates the waiver file, searching startDir and its ancestors.
// Returns "" if none is found.
func FindFile(startDir string) string {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		dir = startDir
	}
	for {
		candidate := filepath.Join(dir, DefaultRelPath)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Load reads and parses a waiver file.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc fileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse waiver file %s: %w", path, err)
	}
	return &Set{Path: path, Waivers: doc.Waivers}, nil
}

// ParseInline extracts all inline ignore directives from raw file content.
func ParseInline(file, content string) []Inline {
	var inlines []Inline
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		// Only consider the comment portion to avoid matching inside string values.
		comment := commentPart(line, file)
		if comment == "" {
			continue
		}
		m := directiveRe.FindStringSubmatch(comment)
		if m == nil {
			continue
		}
		rules := splitRules(m[1])
		tail := m[2]
		inline := Inline{
			File:    file,
			Line:    i + 1,
			Rules:   rules,
			Reason:  firstGroup(reasonRe, tail),
			Expires: firstGroup(expiresRe, tail),
		}
		inlines = append(inlines, inline)
	}
	return inlines
}

// commentPart returns the comment text of a source line, or "" if there is none.
// YAML/Terraform both use "#"; Terraform also supports "//".
func commentPart(line, file string) string {
	idx := strings.Index(line, "#")
	if isTerraform(file) {
		if s := strings.Index(line, "//"); s >= 0 && (idx < 0 || s < idx) {
			return line[s+2:]
		}
	}
	if idx >= 0 {
		return line[idx+1:]
	}
	return ""
}

func isTerraform(file string) bool {
	return strings.EqualFold(filepath.Ext(file), ".tf")
}

func splitRules(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, ShortRuleID(p))
		}
	}
	return out
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// ResourceLine associates a resource ID with the source line where its block starts.
type ResourceLine struct {
	ID   string
	Line int
}

// AttributeInline maps each inline directive to the resource it governs, returning
// resourceID -> directives. A directive placed 1-2 lines above a resource (head
// comment) attaches to that resource; otherwise it attaches to the enclosing block.
func AttributeInline(inlines []Inline, resources []ResourceLine) map[string][]Inline {
	out := make(map[string][]Inline)
	if len(resources) == 0 {
		return out
	}
	sorted := make([]ResourceLine, len(resources))
	copy(sorted, resources)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Line < sorted[j].Line })

	for _, in := range inlines {
		id := attributeOne(in.Line, sorted)
		if id != "" {
			out[id] = append(out[id], in)
		}
	}
	return out
}

func attributeOne(line int, sorted []ResourceLine) string {
	// Head-comment intent: a resource starts 1-2 lines below the directive.
	for _, r := range sorted {
		if r.Line == line+1 || r.Line == line+2 {
			return r.ID
		}
	}
	// Enclosing block: the resource with the largest start line <= directive line.
	id := ""
	for _, r := range sorted {
		if r.Line <= line {
			id = r.ID
		} else {
			break
		}
	}
	return id
}

// Annotate sets the Waiver field on every violation in results that matches a waiver.
// inlineByFile maps file path -> resourceID -> directives (from AttributeInline).
// now is used to determine expiry (inject for deterministic tests).
func (s *Set) Annotate(results []models.FileResult, inlineByFile map[string]map[string][]Inline, now time.Time) {
	for fi := range results {
		fr := &results[fi]
		for vi := range fr.Violations {
			v := &fr.Violations[vi]
			// Inline directives take precedence over central-file waivers.
			if info := matchInline(v, inlineByFile[fr.File], now); info != nil {
				v.Waiver = info
				continue
			}
			if info := s.matchFile(v, now); info != nil {
				v.Waiver = info
			}
		}
	}
}

func matchInline(v *models.RichViolation, byResource map[string][]Inline, now time.Time) *models.WaiverInfo {
	if byResource == nil {
		return nil
	}
	short := ShortRuleID(v.ID)
	for _, in := range byResource[v.ResourceID] {
		if !ruleMatches(in.Rules, short) {
			continue
		}
		return &models.WaiverInfo{
			Status:  statusFor(in.Expires, now),
			Source:  "inline",
			Reason:  in.Reason,
			Expires: in.Expires,
		}
	}
	return nil
}

func (s *Set) matchFile(v *models.RichViolation, now time.Time) *models.WaiverInfo {
	if s == nil {
		return nil
	}
	short := ShortRuleID(v.ID)
	for _, w := range s.Waivers {
		if !ruleMatches([]string{ShortRuleID(w.Rule)}, short) {
			continue
		}
		if w.Resource != "" && !globMatch(w.Resource, v.ResourceID) {
			continue
		}
		if len(w.Files) > 0 && !anyFileMatch(w.Files, v.File) {
			continue
		}
		return &models.WaiverInfo{
			Status:  statusFor(w.Expires, now),
			Source:  "file",
			Reason:  w.Reason,
			Owner:   w.Owner,
			Expires: w.Expires,
		}
	}
	return nil
}

func ruleMatches(patterns []string, shortID string) bool {
	for _, p := range patterns {
		if p == "*" || p == shortID {
			return true
		}
	}
	return false
}

func statusFor(expires string, now time.Time) string {
	if expires == "" {
		return models.WaiverStatusActive
	}
	t, err := time.Parse(dateLayout, expires)
	if err != nil {
		// Unparseable expiry is treated as expired so it gets flagged for cleanup.
		return models.WaiverStatusExpired
	}
	// Expiry is inclusive of the named day.
	if now.Truncate(24 * time.Hour).After(t) {
		return models.WaiverStatusExpired
	}
	return models.WaiverStatusActive
}

// anyFileMatch reports whether path matches any of the file globs. Patterns are
// matched against the path relative to the current working directory (falling back
// to the absolute path).
func anyFileMatch(patterns []string, path string) bool {
	candidates := fileCandidates(path)
	for _, p := range patterns {
		for _, c := range candidates {
			if globMatch(p, c) {
				return true
			}
		}
	}
	return false
}

func fileCandidates(path string) []string {
	out := []string{filepath.ToSlash(path)}
	if abs, err := filepath.Abs(path); err == nil {
		out = append(out, filepath.ToSlash(abs))
		if cwd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(cwd, abs); err == nil {
				out = append(out, filepath.ToSlash(rel))
			}
		}
	}
	return out
}

// globMatch matches a glob pattern supporting "*" (within a path segment) and
// "**" (across segments) against a slash-separated string.
func globMatch(pattern, s string) bool {
	re := globToRegexp(filepath.ToSlash(pattern))
	return re.MatchString(filepath.ToSlash(s))
}

var globCache = map[string]*regexp.Regexp{}

func globToRegexp(pattern string) *regexp.Regexp {
	if re, ok := globCache[pattern]; ok {
		return re
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
				// Consume a following slash so "**/" matches zero directories too.
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	globCache[pattern] = re
	return re
}

// ShortRuleID reduces a full rule ID ("rule:aliyun:foo") to its short form ("foo").
func ShortRuleID(id string) string {
	if !strings.HasPrefix(id, "rule:") && !strings.HasPrefix(id, "pack:") {
		return id
	}
	parts := strings.Split(id, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return id
}
