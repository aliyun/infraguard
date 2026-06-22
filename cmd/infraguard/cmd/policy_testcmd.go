package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/policytest"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
)

var (
	testDir        string
	testRules      []string
	testIaC        string
	testFormat     string
	testAllowEmpty bool
)

var policyTestCmd = &cobra.Command{
	Use:          "test",
	Short:        "", // Set dynamically
	Long:         "", // Set dynamically
	Args:         cobra.NoArgs,
	RunE:         runPolicyTest,
	SilenceUsage: true,
}

func init() {
	policyCmd.AddCommand(policyTestCmd)

	policyTestCmd.Flags().StringVar(&testDir, "dir", "./policies", "Root directory containing rules/ and testdata/")
	policyTestCmd.Flags().StringArrayVar(&testRules, "rule", nil, "Only test the given rule ID (repeatable)")
	policyTestCmd.Flags().StringVar(&testIaC, "iac", "both", "IaC to test: ros, terraform, or both")
	policyTestCmd.Flags().StringVar(&testFormat, "format", "table", "Output format: table or json")
	policyTestCmd.Flags().BoolVar(&testAllowEmpty, "allow-empty", false, "Exit 0 even when no fixtures are found")
}

func runPolicyTest(cmd *cobra.Command, args []string) error {
	if testFormat != "table" && testFormat != "json" {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.ErrFormat }), testFormat)
	}
	switch testIaC {
	case "ros", "terraform", "both":
	default:
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.ErrIaC }), testIaC)
	}

	results, summary, err := policytest.Run(policytest.Options{
		Dir:     testDir,
		RuleIDs: testRules,
		IaC:     testIaC,
	})
	if err != nil {
		return err
	}

	if testFormat == "json" {
		if err := printTestJSON(results, summary); err != nil {
			return err
		}
	} else {
		printTestTable(results, summary)
	}

	if summary.Cases == 0 {
		if testAllowEmpty {
			return nil
		}
		os.Exit(2)
	}
	if summary.Failed > 0 {
		os.Exit(1)
	}
	return nil
}

func printTestTable(results []policytest.CaseResult, summary policytest.Summary) {
	msg := i18n.Msg()
	if len(results) == 0 {
		fmt.Println(msg.PolicyTest.NoFixtures)
		return
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRendition(tw.Rendition{
			Settings: tw.Settings{Separators: tw.Separators{BetweenRows: tw.On}},
		}),
	)
	table.Header(msg.PolicyTest.HeaderRule, msg.PolicyTest.HeaderCase, msg.PolicyTest.HeaderStatus, msg.PolicyTest.HeaderDetail)
	for _, c := range results {
		table.Append(
			wrapText(c.Rule, 36),
			c.Case,
			colorTestStatus(c.Status),
			wrapText(testDetail(c), 40),
		)
	}
	table.Render()

	fmt.Println()
	line := fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.Summary }),
		summary.Rules, summary.Cases, summary.Passed, summary.Failed)
	if summary.Failed > 0 {
		redColor.Println(line)
	} else {
		greenColor.Println(line)
	}
}

func colorTestStatus(status string) string {
	msg := i18n.Msg()
	switch status {
	case policytest.StatusPass:
		return greenColor.Sprint("✓ " + msg.PolicyTest.StatusPass)
	case policytest.StatusFail:
		return redColor.Sprint("✗ " + msg.PolicyTest.StatusFail)
	default:
		return yellowColor.Sprint("! " + msg.PolicyTest.StatusError)
	}
}

// testDetail localizes a case result's reason code into a human-readable string.
func testDetail(c policytest.CaseResult) string {
	switch c.Code {
	case policytest.CodeNoRule:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.DetailNoRule }), c.Detail)
	case policytest.CodeExpectOne:
		return i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.DetailExpect1 })
	case policytest.CodeExpectZero:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.DetailExpect0 }), c.Detail)
	case policytest.CodeLoad:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.DetailLoad }), c.Detail)
	case policytest.CodeLoadTF:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.DetailLoadTF }), c.Detail)
	case policytest.CodeEval:
		return fmt.Sprintf(i18n.Get(func(m *i18n.Messages) string { return m.PolicyTest.DetailEval }), c.Detail)
	}
	return ""
}

func printTestJSON(results []policytest.CaseResult, summary policytest.Summary) error {
	type jsonOut struct {
		SchemaVersion string                  `json:"schema_version"`
		Summary       policytest.Summary      `json:"summary"`
		Results       []policytest.CaseResult `json:"results"`
	}
	out := jsonOut{SchemaVersion: "1.0", Summary: summary, Results: results}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
