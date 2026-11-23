package cmd

import (
	"github.com/spf13/cobra"
)

var lookupCmd = &cobra.Command{
	Use:   "lookup <email>",
	Short: "Look up a public key via CKD protocol",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		save, err := cmd.Flags().GetBool("save")
		if err != nil {
			return err
		}
		jsonOutput, err := cmd.Flags().GetBool("json")
		if err != nil {
			return err
		}
		ctx, stop := commandContext(cmd)
		defer stop()
		return NewLookupCommand(dbPath).Execute(ctx, args[0], save, jsonOutput)
	},
}

func init() {
	lookupCmd.Flags().Bool("save", false, "Save result to local CKD cache")
	lookupCmd.Flags().Bool("json", false, "Output as JSON")
	rootCmd.AddCommand(lookupCmd)
}
