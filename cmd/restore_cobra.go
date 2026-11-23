package cmd

import (
	"github.com/spf13/cobra"
)

var restoreCmd = &cobra.Command{
	Use:   "restore <backup-file>",
	Short: "Import keys and policies from a backup file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return err
		}
		ctx, stop := commandContext(cmd)
		defer stop()
		return NewRestoreCommand(dbPath).Execute(ctx, args[0], force)
	},
}

func init() {
	restoreCmd.Flags().Bool("force", false, "Overwrite existing keys and policies")
	rootCmd.AddCommand(restoreCmd)
}
