package cmd

import (
	"github.com/spf13/cobra"
)

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover an identity key from backup or mnemonic",
}

var recoverFromMnemonicCmd = &cobra.Command{
	Use:   "from-mnemonic",
	Short: "Recover a key from a 24-word recovery phrase and set a key passphrase",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := commandContext(cmd)
		defer stop()
		return NewRecoverCommand(dbPath).ExecuteFromMnemonic(ctx)
	},
}

func init() {
	recoverCmd.AddCommand(recoverFromMnemonicCmd)
	rootCmd.AddCommand(recoverCmd)
}
