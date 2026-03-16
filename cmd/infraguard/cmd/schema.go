package cmd

import (
	"fmt"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
	"github.com/aliyun/infraguard/pkg/providers/ros"
	"github.com/spf13/cobra"
)

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Manage ROS resource type schema",
}

var schemaUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update ROS resource type schema from API",
	RunE: func(cmd *cobra.Command, args []string) error {
		msg := i18n.Msg()

		cred, err := ros.LoadCredentials()
		if err != nil {
			return fmt.Errorf("%s: %w", msg.Errors.ROSFailedLoadCredentials, err)
		}

		client, err := ros.NewClient(cred)
		if err != nil {
			return err
		}

		fmt.Println(i18n.Get(func(m *i18n.Messages) string { return m.Schema.Updating }))

		count, err := schema.FetchAndSave(client, &schema.FetchOptions{
			Logger: func(format string, args ...interface{}) {
				fmt.Printf(format+"\n", args...)
			},
		})
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.Get(func(m *i18n.Messages) string { return m.Schema.UpdateFailed }), err)
		}

		fmt.Printf(i18n.Get(func(m *i18n.Messages) string { return m.Schema.UpdateSuccess })+"\n", count)
		return nil
	},
}

func init() {
	schemaCmd.AddCommand(schemaUpdateCmd)
}
