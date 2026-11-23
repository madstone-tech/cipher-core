package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Export keys and policies to a backup file",
	Long: `Export keys and policies to a backup file.

The backup holds wrapped private keys and their salts: store it securely.
Without --output it goes to ~/.mdstn/backups/cipher-backup-YYYYMMDD-HHMMSS.json
(folder mode 0700, file mode 0600); when that name is taken (two backups in
one second), -2, -3, ... is added. A backup never replaces a file, with or
without --output, and never writes into the folder of the key database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		numbered := output == ""
		if numbered {
			if output, err = defaultBackupPath(time.Now()); err != nil {
				return err
			}
		}
		ctx, stop := commandContext(cmd)
		defer stop()
		return NewBackupCommand(dbPath).Execute(ctx, output, numbered)
	},
}

func init() {
	backupCmd.Flags().StringP("output", "o", "", "Output file path; never replaces a file (default: ~/.mdstn/backups/cipher-backup-YYYYMMDD-HHMMSS.json)")
	rootCmd.AddCommand(backupCmd)
}

// defaultBackupPath returns ~/.mdstn/backups/cipher-backup-YYYYMMDD-HHMMSS.json
// and keeps ~/.mdstn and ~/.mdstn/backups at mode 0700 (it tightens a looser
// existing mode). A backup holds wrapped private keys and their salts, so it
// does not go into the working directory, which can be a Git working copy.
// The time in the name keeps backups of the same day apart; the backup is
// also created exclusively, so it never replaces an earlier one (S-6).
func defaultBackupPath(now time.Time) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	base := filepath.Join(home, ".mdstn")
	dir := filepath.Join(base, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	for _, d := range []string{base, dir} {
		if err := os.Chmod(d, 0o700); err != nil {
			return "", fmt.Errorf("restrict %s to mode 0700: %w", d, err)
		}
	}
	return filepath.Join(dir, fmt.Sprintf("cipher-backup-%s.json", now.Format("20060102-150405"))), nil
}
