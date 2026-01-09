package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/config"
	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
	Long:  "",
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long:  "",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Long:  "",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Remove a configuration value",
	Long:  "",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigUnset,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration values",
	Long:  "",
	Args:  cobra.NoArgs,
	RunE:  runConfigList,
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configUnsetCmd)
	configCmd.AddCommand(configListCmd)
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	// Validate key
	if !config.IsValidKey(key) {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.Config.Errors.UnknownKey }), key, strings.Join(config.ValidKeys, ", "))
	}

	// Validate value
	if err := config.ValidateValue(key, value); err != nil {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.Config.Errors.InvalidValue }), key, value, strings.Join(config.ValidLangValues, ", "))
	}

	// Load current config
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Set value
	cfg.Set(key, value)

	// Save config
	if err := config.Save(cfg); err != nil {
		return err
	}

	fmt.Println(i18n.Get(func(m *i18n.Messages) string { return m.Config.SetSuccess }))
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	// Validate key
	if !config.IsValidKey(key) {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.Config.Errors.UnknownKey }), key, strings.Join(config.ValidKeys, ", "))
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Get and print value
	value := cfg.Get(key)
	if value != "" {
		fmt.Println(value)
	}

	return nil
}

func runConfigUnset(cmd *cobra.Command, args []string) error {
	key := args[0]

	// Validate key
	if !config.IsValidKey(key) {
		return fmt.Errorf(i18n.Get(func(m *i18n.Messages) string { return m.Config.Errors.UnknownKey }), key, strings.Join(config.ValidKeys, ", "))
	}

	// Load current config
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Unset value
	cfg.Unset(key)

	// Save config
	if err := config.Save(cfg); err != nil {
		return err
	}

	fmt.Println(i18n.Get(func(m *i18n.Messages) string { return m.Config.UnsetSuccess }))
	return nil
}

func runConfigList(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Get all values as map
	values := cfg.ToMap()

	// Sort keys for consistent output
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Print key=value pairs
	msg := i18n.Msg()
	for _, k := range keys {
		fmt.Printf(msg.Config.ListFormat+"\n", k, values[k])
	}

	return nil
}

// updateConfigCommandDescriptions updates config command descriptions based on current language.
func updateConfigCommandDescriptions() {
	configCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Config.Short })
	configCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Config.Long }))

	configSetCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Config.Set.Short })
	configSetCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Config.Set.Long }))

	configGetCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Config.Get.Short })
	configGetCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Config.Get.Long }))

	configUnsetCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Config.Unset.Short })
	configUnsetCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Config.Unset.Long }))

	configListCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Config.List.Short })
	configListCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Config.List.Long }))
}
