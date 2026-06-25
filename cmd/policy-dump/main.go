// Command policy-dump exports rule modules and metadata as JSON for the wasm
// playground. The wasm binary cannot embed the policy index (its init exceeds
// wasm limits), so rules are shipped as a data file the browser fetches and
// passes back in. The payload carries per-IaC implementations plus rule/pack
// metadata so the playground can offer the same policy picker as the server.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
)

type implOut struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type ruleOut struct {
	ID       string             `json:"id"`        // short id (e.g. "oss-bucket-only-https-enabled")
	Name     models.I18nString  `json:"name"`      // localized name
	Severity string             `json:"severity"`  // high | medium | low
	IaCTypes []string           `json:"iac_types"` // supported IaC types
	Impls    map[string]implOut `json:"impls"`     // per-IaC implementation modules
}

type packOut struct {
	ID    string            `json:"id"`    // short id
	Name  models.I18nString `json:"name"`  // localized name
	Rules []string          `json:"rules"` // member rule short ids
}

func shortID(id string) string {
	parts := strings.Split(id, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return id
}

func main() {
	pack := flag.String("pack", "quick-start-compliance-pack", "Pack ID to export (empty = all rules)")
	out := flag.String("out", "", "Output file (default: stdout)")
	flag.Parse()

	loader, err := policy.LoadWithFallback()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load policies:", err)
		os.Exit(1)
	}

	// Resolve the set of rules to export. When a specific pack is requested only
	// that pack is exposed in the picker; otherwise every pack is included.
	var ruleList []*models.Rule
	var exportPacks []*models.Pack
	if *pack == "" {
		ruleList = loader.GetAllRules()
		exportPacks = loader.GetAllPacks()
	} else {
		p := loader.GetPack(*pack)
		if p == nil {
			p = loader.GetPack("pack:aliyun:" + *pack)
		}
		if p == nil {
			fmt.Fprintln(os.Stderr, "pack not found:", *pack)
			os.Exit(1)
		}
		for _, id := range p.RuleIDs {
			if r := loader.GetRule(id); r != nil {
				ruleList = append(ruleList, r)
			}
		}
		exportPacks = []*models.Pack{p}
	}

	rules := make([]ruleOut, 0, len(ruleList))
	for _, r := range ruleList {
		ro := ruleOut{
			ID:       shortID(r.ID),
			Name:     r.Name,
			Severity: r.Severity,
			IaCTypes: r.IaCTypes,
			Impls:    map[string]implOut{},
		}
		for _, iac := range r.IaCTypes {
			if impl := r.Implementations[iac]; impl != nil && impl.Content != "" {
				ro.Impls[iac] = implOut{Path: impl.FilePath, Content: impl.Content}
			} else if r.Content != "" {
				ro.Impls[iac] = implOut{Path: r.FilePath, Content: r.Content}
			}
		}
		// Fall back to the legacy single implementation when IaCTypes is empty.
		if len(ro.Impls) == 0 && r.Content != "" {
			ro.Impls["ros"] = implOut{Path: r.FilePath, Content: r.Content}
			if len(ro.IaCTypes) == 0 {
				ro.IaCTypes = []string{"ros"}
			}
		}
		rules = append(rules, ro)
	}

	// Export pack metadata (members restricted to the exported rule set).
	exported := map[string]bool{}
	for _, r := range rules {
		exported[r.ID] = true
	}
	var packs []packOut
	for _, p := range exportPacks {
		var members []string
		for _, id := range p.RuleIDs {
			if sid := shortID(id); exported[sid] {
				members = append(members, sid)
			}
		}
		if len(members) == 0 {
			continue
		}
		packs = append(packs, packOut{ID: shortID(p.ID), Name: p.Name, Rules: members})
	}

	payload := map[string]interface{}{
		"lib_modules": loader.GetLibModules(),
		"rules":       rules,
		"packs":       packs,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %d rules, %d packs to %s\n", len(rules), len(packs), *out)
}
