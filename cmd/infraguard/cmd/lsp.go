package cmd

import (
	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/lsp"
	"github.com/spf13/cobra"
)

var lspCmd = &cobra.Command{
	Use:   "lsp",
	Short: "Start ROS Language Server",
	RunE: func(cmd *cobra.Command, args []string) error {
		server := lsp.NewServer()
		return server.Run()
	},
}

func init() {
	lspCmd.Flags().Bool("stdio", false, "Use stdio transport (default, accepted for editor compatibility)")
}

func updateLSPCommandDescriptions() {
	lspCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.LSP.Short })
	lspCmd.Long = i18n.Get(func(m *i18n.Messages) string { return m.LSP.Long })
}
