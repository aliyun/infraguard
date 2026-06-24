// Command policy-dump exports rule modules as JSON for the wasm playground.
// The wasm binary cannot embed the policy index (its init exceeds wasm limits),
// so rules are shipped as a data file the browser fetches and passes back in.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/aliyun/infraguard/pkg/policy"
)

func main() {
	pack := flag.String("pack", "quick-start-compliance-pack", "Pack ID to export (empty = all rules)")
	iac := flag.String("iac", "ros", "IaC implementation to export")
	out := flag.String("out", "", "Output file (default: stdout)")
	flag.Parse()

	loader, err := policy.LoadWithFallback()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load policies:", err)
		os.Exit(1)
	}

	modules := map[string]string{}
	collect := func(id string) {
		rule := loader.GetRule(id)
		if rule == nil {
			return
		}
		if impl := rule.Implementations[*iac]; impl != nil && impl.Content != "" {
			modules[impl.FilePath] = impl.Content
		} else if rule.Content != "" {
			modules[rule.FilePath] = rule.Content
		}
	}

	if *pack == "" {
		for _, rule := range loader.GetAllRules() {
			collect(rule.ID)
		}
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
			collect(id)
		}
	}

	payload := map[string]interface{}{
		"lib_modules": loader.GetLibModules(),
		"modules":     modules,
		"rule_count":  len(modules),
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
	fmt.Fprintf(os.Stderr, "wrote %d modules to %s\n", len(modules), *out)
}
