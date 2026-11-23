package cmd

import (
	"github.com/spf13/cobra"
)

// checkExpiryCmd is the one-shot key-expiry detection command.
// It uses the SQLite store and a NoopDispatcher (no webhook HTTP delivery).
var checkExpiryCmd = &cobra.Command{
	Use:   "check-expiry",
	Short: "Scan keys for expiry and record deduped notifications",
	Long: `Scan all keys that have an expiry date and emit deduped notifications.

For each key that is expired, expiring within 1 day, or expiring within 7 days,
a notification record is written (preventing duplicate alerts) and the event is
logged to the audit store.

No webhook HTTP delivery is performed by this one-shot command — that path is
handled by the server's hourly background loop. Use this command in scripts or
cron jobs to detect expiring keys from the CLI.

Examples:
  $ mdstn-cipher check-expiry
  $ mdstn-cipher check-expiry --db /path/to/cipher.db`,
	RunE: runCheckExpiry,
}

func init() {
	rootCmd.AddCommand(checkExpiryCmd)
}

func runCheckExpiry(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	c := NewCheckExpiryCommand(dbPath)
	return c.Execute(ctx)
}
