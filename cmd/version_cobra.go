package cmd

import (
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOutput, err := cmd.Flags().GetBool("json")
		if err != nil {
			return err
		}
		vc := &VersionCommand{}
		return vc.Execute(jsonOutput)
	},
}

func init() {
	versionCmd.Flags().Bool("json", false, "Output as JSON")
	rootCmd.AddCommand(versionCmd)

	// Use Cobra's built-in version support for --version on root
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("mdstn-cipher {{.Version}}\n")
}
