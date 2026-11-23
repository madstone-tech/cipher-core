package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	keyType       string
	keyAlias      string
	keyFormat     string
	keyEmail      string
	serverURL     string
	keyExpiresIn  string
	keyExpiresAt  string
	keyPassphrase string
	yesFlag       bool
)

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage encryption keys",
	Long:  `Create, list, and manage encryption keys.`,
}

// keysListCmd lists all keys
var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	RunE:  runKeysList,
}

// keysCreateCmd creates a new key
var keysCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key",
	Long: `Create a new encryption key.

By default, creates an X25519 keypair for hybrid encryption.
Use --type to specify AES256 for symmetric encryption.
Use --expires-in or --expires-at to set an optional expiry date.

Examples:
  $ mdstn-cipher keys create
  $ mdstn-cipher keys create --alias project-key
  $ mdstn-cipher keys create --alias project-key --expires-in 90d
  $ mdstn-cipher keys create --alias project-key --expires-in 4w
  $ mdstn-cipher keys create --alias project-key --expires-at 2026-12-31T00:00:00Z`,
	RunE: runKeysCreate,
}

// keysDeleteCmd deletes a key
var keysDeleteCmd = &cobra.Command{
	Use:   "delete <key-id>",
	Short: "Delete a key",
	Args:  cobra.ExactArgs(1),
	RunE:  runKeysDelete,
}

// keysAliasCmd sets an alias for a key
var keysAliasCmd = &cobra.Command{
	Use:   "alias <key-id> <alias>",
	Short: "Set an alias for a key",
	Args:  cobra.ExactArgs(2),
	RunE:  runKeysAlias,
}

// keysExportCmd exports a key
var keysExportCmd = &cobra.Command{
	Use:   "export <key-id>",
	Short: "Export a key",
	Long: `Export a key to a file. --output is required. It replaces an existing
file, but never into the folder of the key database. The file has mode 0600.

The export holds the WRAPPED private key (encrypted with your key passphrase),
not the raw key. The PEM label is "MDSTN WRAPPED X25519 PRIVATE KEY". To
restore a key, use "backup"/"restore" or the 24-word recovery phrase.

Formats:
  pem - PEM-encoded key (default)
  raw - Raw binary key

Examples:
  $ mdstn-cipher keys export abc123 --output key.pem
  $ mdstn-cipher keys export abc123 --format raw --output key.bin`,
	Args: cobra.ExactArgs(1),
	RunE: runKeysExport,
}

// keysPublishCmd publishes a key to CKD
var keysPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish your public key to CKD",
	Long: `Publish your X25519 public key to the Cipher Key Directory (CKD).

This makes your public key discoverable by email, allowing others to
encrypt files for you using: mdstn-cipher encrypt file.pdf --for you@domain.com

Currently publishes to the Madstone hosted directory (keys.madstone.dev).
In the future, will support self-hosted CKD servers.

Examples:
  $ mdstn-cipher keys publish --email alice@team.com`,
	RunE: runKeysPublish,
}

// keysUnpublishCmd unpublishes a key from CKD
var keysUnpublishCmd = &cobra.Command{
	Use:   "unpublish",
	Short: "Unpublish your public key from CKD",
	Long: `Remove your X25519 public key from the Cipher Key Directory (CKD).

This prevents others from encrypting files for you using your email address.
You can republish at any time.

Examples:
  $ mdstn-cipher keys unpublish --email alice@team.com`,
	RunE: runKeysUnpublish,
}

func init() {
	rootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysCreateCmd)
	keysCmd.AddCommand(keysDeleteCmd)
	keysCmd.AddCommand(keysAliasCmd)
	keysCmd.AddCommand(keysExportCmd)
	keysCmd.AddCommand(keysPublishCmd)
	keysCmd.AddCommand(keysUnpublishCmd)

	keysCreateCmd.Flags().StringVar(&keyType, "type", "x25519", "key type (x25519 or aes256)")
	keysCreateCmd.Flags().StringVar(&keyAlias, "alias", "", "key alias")
	keysCreateCmd.Flags().StringVar(&keyExpiresIn, "expires-in", "", "key lifetime as a duration (e.g. 30d, 4w, 720h)")
	keysCreateCmd.Flags().StringVar(&keyExpiresAt, "expires-at", "", "absolute expiry timestamp in RFC3339 format (e.g. 2026-12-31T00:00:00Z)")
	keysCreateCmd.Flags().StringVar(&keyPassphrase, "key-passphrase", "", "key passphrase (overrides --key-passphrase-file and MDSTN_KEY_PASSPHRASE)")
	keysCreateCmd.Flags().StringVar(&keyPassphraseFile, "key-passphrase-file", "", "read the key passphrase from a file, or - for stdin (overrides MDSTN_KEY_PASSPHRASE)")
	keysCreateCmd.Flags().BoolVar(&yesFlag, "yes", false, "skip the 3-word recovery phrase confirmation (required without a terminal)")

	keysExportCmd.Flags().StringVar(&keyFormat, "format", "pem", "export format (pem or raw)")
	keysExportCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path")

	keysPublishCmd.Flags().StringVar(&keyEmail, "email", "", "your email address (required)")
	keysPublishCmd.Flags().StringVar(&serverURL, "server-url", "", "server URL (optional, defaults to CIPHER_SERVER_URL env var)")
	if err := keysPublishCmd.MarkFlagRequired("email"); err != nil {
		panic(err)
	}

	keysUnpublishCmd.Flags().StringVar(&keyEmail, "email", "", "your email address (required)")
	keysUnpublishCmd.Flags().StringVar(&serverURL, "server-url", "", "server URL (optional, defaults to CIPHER_SERVER_URL env var)")
	if err := keysUnpublishCmd.MarkFlagRequired("email"); err != nil {
		panic(err)
	}
}

func runKeysList(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.List(ctx)
}

func runKeysCreate(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()

	// Priority: --key-passphrase > --key-passphrase-file > MDSTN_KEY_PASSPHRASE
	// (applied in Create) > prompt (in the usecase).
	passphrase := keyPassphrase
	if passphrase == "" && cmd.Flags().Changed("key-passphrase-file") {
		var err error
		passphrase, err = secretFromFile(keyPassphraseFile)
		if err != nil {
			return fmt.Errorf("--key-passphrase-file: %w", err)
		}
	}

	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.Create(ctx, keyType, keyAlias, keyExpiresIn, keyExpiresAt, passphrase, yesFlag)
}

func runKeysDelete(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	keyID := args[0]
	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.Delete(ctx, keyID)
}

func runKeysAlias(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	keyID := args[0]
	alias := args[1]
	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.Alias(ctx, keyID, alias)
}

func runKeysExport(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	keyID := args[0]
	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.Export(ctx, keyID, keyFormat, outputPath)
}

func runKeysPublish(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.Publish(ctx, keyEmail, serverURL)
}

func runKeysUnpublish(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	keysCommand := NewKeysCommand(dbPath, jsonOutput, verbose)
	return keysCommand.Unpublish(ctx, keyEmail, serverURL)
}
