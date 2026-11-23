package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
)

var (
	cfgFile    string
	dbPath     string
	verbose    bool
	jsonOutput bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "mdstn-cipher",
	Short: "Zero-config file encryption with managed key lifecycle",
	Long: `Madstone Cipher - File encryption and key management tool

Encrypt files with zero configuration, share encrypted files via email-based
key discovery, and manage encryption keys with a simple CLI.`,
	// main prints the error once and maps it to the exit code (ExitCode).
	SilenceErrors:     true,
	PersistentPreRunE: persistentPreRun,
}

// Execute runs the root command. The caller maps the error with ExitCode.
func Execute() error {
	return rootCmd.Execute()
}

// initErr holds the initConfig result. cobra.OnInitialize runs initConfig for
// every command, including commands that a consuming application attaches with
// its own PersistentPreRunE (cobra runs only the nearest persistent hook).
var initErr error

func init() {
	cobra.OnInitialize(func() { initErr = initConfig() })

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.mdstn/cipher.toml)")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "database path (default: ~/.mdstn/cipher.db)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
}

// persistentPreRun runs after flag and argument parsing, before every RunE.
// Usage text is for parse errors only: from here on, an error is a runtime
// error and cobra must not print the usage for it.
func persistentPreRun(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true
	return initErr
}

// commandContext returns the context for one command run. SIGINT and SIGTERM
// cancel it; the caller MUST call the returned stop function.
func commandContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

func initConfig() error {
	// Set default paths
	if dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("find home directory: %w", err)
		}

		mdstDir := filepath.Join(home, ".mdstn")
		dbPath = filepath.Join(mdstDir, "cipher.db")

		// Create directory if it doesn't exist
		if err := os.MkdirAll(mdstDir, 0o700); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}

		// Remove stale staged files left by previously crashed processes.
		fh := cli.NewFileHandler()
		if err := fh.CleanupStaleTempFiles(mdstDir); err != nil {
			slog.Warn("stale temp file cleanup failed", "error", err)
		}
	}
	return nil
}

// GetRootCommand exposes the composed root command (with all core
// subcommands + global flags) so a consuming application can attach its own
// subcommands and run one binary.
func GetRootCommand() *cobra.Command { return rootCmd }
