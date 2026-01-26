package cmd

import (
	"os"
	"strings"

	"github.com/aliyun/infraguard/pkg/config"
	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/spf13/cobra"
)

var globalLang string

var rootCmd = &cobra.Command{
	Use:           "infraguard",
	Short:         "InfraGuard - IaC compliance pre-check CLI", // Default, will be updated
	Long:          "",                                          // Will be updated
	SilenceErrors: true,
}

// Execute runs the root command
func Execute() error {
	// Parse --lang flag early before cobra processes commands
	parseLangFlag()

	// Initialize i18n with language priority:
	// 1. --lang flag (highest priority)
	// 2. config file lang setting
	// 3. system language detection (lowest priority)
	if globalLang != "" {
		i18n.SetLanguage(globalLang)
	} else if configLang := config.GetLang(); configLang != "" {
		i18n.SetLanguage(configLang)
	} else {
		i18n.Init()
	}

	// Update command descriptions and templates based on current language
	updateCommandDescriptions()
	setUsageTemplate()

	return rootCmd.Execute()
}

// parseLangFlag manually parses the --lang flag from os.Args
func parseLangFlag() {
	for i, arg := range os.Args {
		if arg == "--lang" && i+1 < len(os.Args) {
			globalLang = os.Args[i+1]
			return
		}
		if len(arg) > 7 && arg[:7] == "--lang=" {
			globalLang = arg[7:]
			return
		}
	}
}

func init() {
	// Add global --lang flag
	rootCmd.PersistentFlags().StringVar(&globalLang, "lang", "",
		"Output language (en or zh, default: auto-detect)")

	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(configCmd)
}

// updateCommandDescriptions updates all command descriptions based on current language.
func updateCommandDescriptions() {
	msg := i18n.Msg()

	// Root command
	rootCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Root.Short })
	rootCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Root.Long }))

	// Policy command
	policyCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Policy.Short })
	policyCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Policy.Long }))

	// Policy update command
	policyUpdateCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.PolicyUpdate.Short })
	policyUpdateCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.PolicyUpdate.Long }))

	// Policy get command
	policyGetCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.PolicyGet.Short })
	policyGetCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.PolicyGet.Long }))

	// Policy list command
	policyListCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.PolicyList.Short })
	policyListCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.PolicyList.Long }))

	// Policy validate command
	policyValidateCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.PolicyValidate.Short })
	policyValidateCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.PolicyValidate.Long }))

	// Policy format command
	policyFormatCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.PolicyFormat.Short })
	policyFormatCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.PolicyFormat.Long }))

	// Scan command
	scanCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Scan.Short })
	scanCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Scan.Long }))

	// Version command
	updateVersionCommandDescriptions()

	// Update command
	updateUpdateCommandDescriptions()

	// Update flag descriptions
	if langFlag := rootCmd.PersistentFlags().Lookup("lang"); langFlag != nil {
		langFlag.Usage = i18n.Get(func(m *i18n.Messages) string { return m.LangFlag })
	}

	// Update scan command flags
	updateScanFlagDescriptions()

	// Update policy update command flags
	updatePolicyUpdateFlagDescriptions()

	// Update policy format command flags
	updatePolicyFormatFlagDescriptions()

	// Update config command descriptions
	updateConfigCommandDescriptions()

	// Update help flag description for root and all subcommands
	helpFlagDesc := "help for {{.Name}}"
	if i18n.GetLanguage() == "zh" {
		helpFlagDesc = "{{.Name}} 的帮助信息"
	}
	// Traverse all commands to update help flag
	updateHelpFlags(rootCmd, helpFlagDesc)

	// Update built-in commands (completion, help)
	for _, cmd := range rootCmd.Commands() {
		switch cmd.Name() {
		case "completion":
			cmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Completion.Short })
		case "help":
			cmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Help.Short })
			cmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Help.Long }))
		}
	}

	// Set custom help command
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: msg.Help.Short,
		Long:  strings.TrimSpace(msg.Help.Long),
		Run: func(c *cobra.Command, args []string) {
			cmd, _, e := c.Root().Find(args)
			if cmd == nil || e != nil {
				msg := i18n.Msg()
				c.Printf(msg.Errors.UnknownHelpTopic+"\n", args)
				c.Root().Usage()
			} else {
				cmd.InitDefaultHelpFlag()
				cmd.Help()
			}
		},
	})

	// Set custom completion command
	completionCmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: msg.Completion.Short,
		Long: strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string {
			return m.Completion.Short
		})),
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}

	// Remove existing completion command if any and add our custom one
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "completion" {
			rootCmd.RemoveCommand(cmd)
			break
		}
	}
	rootCmd.AddCommand(completionCmd)
}

// updateScanFlagDescriptions updates scan command flag descriptions.
func updateScanFlagDescriptions() {
	msg := i18n.Msg()
	flags := scanCmd.Flags()

	if f := flags.Lookup("policy"); f != nil {
		f.Usage = msg.Scan.PolicyFlag
	}
	if f := flags.Lookup("input"); f != nil {
		f.Usage = msg.Scan.InputFlag
	}
	if f := flags.Lookup("format"); f != nil {
		f.Usage = msg.Scan.FormatFlag
	}
	if f := flags.Lookup("output"); f != nil {
		f.Usage = msg.Scan.OutputFlag
	}
}

// updatePolicyUpdateFlagDescriptions updates policy update command flag descriptions.
func updatePolicyUpdateFlagDescriptions() {
	msg := i18n.Msg()
	flags := policyUpdateCmd.Flags()

	if f := flags.Lookup("repo"); f != nil {
		f.Usage = msg.PolicyUpdate.RepoFlag
	}
	if f := flags.Lookup("version"); f != nil {
		f.Usage = msg.PolicyUpdate.VersionFlag
	}
}

// updatePolicyFormatFlagDescriptions updates policy format command flag descriptions.
func updatePolicyFormatFlagDescriptions() {
	msg := i18n.Msg()
	flags := policyFormatCmd.Flags()

	if f := flags.Lookup("write"); f != nil {
		f.Usage = msg.PolicyFormat.WriteFlag
	}
	if f := flags.Lookup("diff"); f != nil {
		f.Usage = msg.PolicyFormat.DiffFlag
	}
}

// updateHelpFlags updates help flag description for a command and its subcommands.
func updateHelpFlags(cmd *cobra.Command, desc string) {
	// Replace template in description
	cmdDesc := strings.ReplaceAll(desc, "{{.Name}}", cmd.Name())

	// Set help flag description
	cmd.InitDefaultHelpFlag()
	if helpFlag := cmd.Flags().Lookup("help"); helpFlag != nil {
		helpFlag.Usage = cmdDesc
	}

	// Recurse into subcommands
	for _, subCmd := range cmd.Commands() {
		updateHelpFlags(subCmd, desc)
	}
}

// setUsageTemplate sets a localized usage template for cobra.
func setUsageTemplate() {
	msg := i18n.Msg()

	usageTemplate := msg.Usage + `:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

` + msg.Aliases + `:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

` + msg.Examples + `:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

` + msg.AvailableCommands + `:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

` + msg.AdditionalCommands + `:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

` + msg.Flags + `:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

` + msg.GlobalFlags + `:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

` + msg.AdditionalHelp + `{{end}}
`

	rootCmd.SetUsageTemplate(usageTemplate)

	// Also set for all subcommands
	for _, cmd := range rootCmd.Commands() {
		cmd.SetUsageTemplate(usageTemplate)
		for _, subCmd := range cmd.Commands() {
			subCmd.SetUsageTemplate(usageTemplate)
		}
	}
}
