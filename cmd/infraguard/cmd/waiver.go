package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/waiver"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
)

var waiverFile string

var waiverCmd = &cobra.Command{
	Use:   "waiver",
	Short: "", // Set dynamically
	Long:  "", // Set dynamically
}

var waiverListCmd = &cobra.Command{
	Use:          "list",
	Short:        "", // Set dynamically
	Args:         cobra.NoArgs,
	RunE:         runWaiverList,
	SilenceUsage: true,
}

var waiverLintCmd = &cobra.Command{
	Use:          "lint",
	Short:        "", // Set dynamically
	Args:         cobra.NoArgs,
	RunE:         runWaiverLint,
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(waiverCmd)
	waiverCmd.AddCommand(waiverListCmd)
	waiverCmd.AddCommand(waiverLintCmd)

	waiverCmd.PersistentFlags().StringVar(&waiverFile, "waivers", "",
		"Path to waiver file (default: auto-detect .infraguard/waivers.yaml)")
	waiverLintCmd.Flags().StringVar(&waiverRulesDir, "rules-dir", "",
		"Also treat rules under this directory as known (for custom rules)")
}

var waiverRulesDir string

// resolveWaiverSet loads the waiver set from the flag or by auto-detection.
func resolveWaiverSet() (*waiver.Set, error) {
	path := waiverFile
	if path == "" {
		path = waiver.FindFile(".")
	}
	if path == "" {
		return nil, fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.NotFound }), waiver.DefaultRelPath)
	}
	return waiver.Load(path)
}

func runWaiverList(cmd *cobra.Command, args []string) error {
	msg := i18n.Msg()
	set, err := resolveWaiverSet()
	if err != nil {
		return err
	}

	statuses := set.List(time.Now())
	if len(statuses) == 0 {
		fmt.Printf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.List.None })+"\n", set.Path)
		return nil
	}

	boldColor.Printf("\n"+i18n.Get(func(m *i18n.Messages) string { return m.Waiver.List.Title })+"\n\n", len(statuses), set.Path)

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRendition(tw.Rendition{
			Settings: tw.Settings{Separators: tw.Separators{BetweenRows: tw.On}},
		}),
	)
	table.Header(msg.Waiver.List.HeaderRule, msg.Waiver.List.HeaderResource, msg.Waiver.List.HeaderStatus, msg.Waiver.List.HeaderExpires, msg.Waiver.List.HeaderReason)
	for _, s := range statuses {
		resource := s.Waiver.Resource
		if resource == "" {
			resource = "*"
		}
		expires := s.Expires
		if expires == "" {
			expires = "-"
		}
		table.Append(
			wrapText(s.Waiver.Rule, 30),
			wrapText(resource, 20),
			colorWaiverState(s.State),
			expires,
			wrapText(s.Waiver.Reason, 40),
		)
	}
	table.Render()
	fmt.Println()
	return nil
}

func colorWaiverState(state string) string {
	msg := i18n.Msg()
	switch state {
	case "active":
		return greenColor.Sprint(msg.Waiver.List.StateActive)
	case "expired":
		return redColor.Sprint(msg.Waiver.List.StateExpired)
	default: // permanent
		return yellowColor.Sprint(msg.Waiver.List.StatePermanent)
	}
}

// customRuleDirs returns directories to scan for custom rules during lint.
func customRuleDirs() []string {
	var dirs []string
	if waiverRulesDir != "" {
		dirs = append(dirs, waiverRulesDir)
	}
	// Convention: a workspace policies/rules directory next to the project.
	if info, err := os.Stat(filepath.Join("policies", "rules")); err == nil && info.IsDir() {
		dirs = append(dirs, filepath.Join("policies", "rules"))
	}
	return dirs
}

func runWaiverLint(cmd *cobra.Command, args []string) error {
	set, err := resolveWaiverSet()
	if err != nil {
		return err
	}

	// Build the set of known short rule IDs for the unknown-rule check, combining
	// built-in rules with any custom rules discovered in the workspace.
	knownRules := make(map[string]bool)
	var extraModules []policy.RegoModule
	if loader, err := policy.LoadWithFallback(); err == nil {
		for _, rule := range loader.GetAllRules() {
			knownRules[waiver.ShortRuleID(rule.ID)] = true
		}
		for name, content := range loader.GetLibModules() {
			extraModules = append(extraModules, policy.RegoModule{Path: name, Content: content})
		}
	}
	for _, dir := range customRuleDirs() {
		if rules, err := policy.DiscoverRulesWithExtraModules(dir, extraModules); err == nil {
			for _, rule := range rules {
				knownRules[waiver.ShortRuleID(rule.ID)] = true
			}
		}
	}
	if len(knownRules) == 0 {
		knownRules = nil // Skip the unknown-rule check if nothing is loadable.
	}

	issues := set.Lint(knownRules, time.Now())
	if len(issues) == 0 {
		greenColor.Printf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.Valid })+"\n", len(set.Waivers), set.Path)
		return nil
	}

	errorCount := 0
	for _, issue := range issues {
		label := fmt.Sprintf("waiver #%d (%s)", issue.Index+1, issue.Rule)
		if issue.Severity == waiver.IssueError {
			errorCount++
			redColor.Printf("✗ %s: %s\n", label, lintMessage(issue))
		} else {
			yellowColor.Printf("⚠ %s: %s\n", label, lintMessage(issue))
		}
	}

	fmt.Println()
	if errorCount > 0 {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.Summary }), errorCount, len(issues)-errorCount, set.Path)
	}
	yellowColor.Printf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.WarnSummary })+"\n", len(issues), set.Path)
	return nil
}

// lintMessage localizes a lint issue code into a human-readable string.
func lintMessage(issue waiver.Issue) string {
	switch issue.Code {
	case waiver.CodeMissingRule:
		return i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.MissingRule })
	case waiver.CodeMissingReason:
		return i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.MissingReason })
	case waiver.CodeUnknownRule:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.UnknownRule }), issue.Detail)
	case waiver.CodeInvalidExpires:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.InvalidExpires }), issue.Detail)
	case waiver.CodeExpired:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.Expired }), issue.Detail)
	case waiver.CodePermanent:
		return i18n.Get(func(m *i18n.Messages) string { return m.Waiver.Lint.Permanent })
	}
	return ""
}
