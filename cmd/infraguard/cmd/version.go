package cmd

import (
	"fmt"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/open-policy-agent/opa/version"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags
var Version = "0.1.2"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information", // Will be updated by i18n
	Long:  "",                          // Will be updated by i18n
	Run: func(cmd *cobra.Command, args []string) {
		msg := i18n.Msg()
		fmt.Printf("%s: %s\n", msg.Version.InfraGuard, Version)
		fmt.Printf("%s: %s\n", msg.Version.OPA, version.Version)
	},
}
