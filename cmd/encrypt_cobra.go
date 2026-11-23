package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	forEmail          string
	recipientFlags    []string
	recipientKeyFlags []string
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt <file>",
	Short: "Encrypt a file",
	Long: `Encrypt a file. Without a method flag, the command asks for a file password.

1. With a file password: No key storage required. The first form asks for it
   $ mdstn-cipher encrypt secret.pdf
   $ mdstn-cipher encrypt secret.pdf --password 'my file password'

2. With a file password from a file (no terminal needed; - reads stdin)
   $ mdstn-cipher encrypt secret.pdf --password-file pw.txt

3. For yourself: Encrypts to your default key. If you have no default key,
   the command creates one and protects it with this passphrase
   $ mdstn-cipher encrypt secret.pdf --key-passphrase-file key-pass.txt

4. For a recipient: Discovers their public key via CKD
   $ mdstn-cipher encrypt secret.pdf --for alice@team.com

5. For multiple recipients: Encrypts to multiple keys so any one can decrypt
   $ mdstn-cipher encrypt secret.pdf --recipient alice@team.com --recipient bob@team.com
   $ mdstn-cipher encrypt secret.pdf --recipient key-id-1,key-id-2

6. For a raw X25519 public key (base64 of 32 bytes, or a file that holds it)
   $ mdstn-cipher encrypt secret.pdf --recipient-key alice.pub

Output: without --output, the result goes to <file>.mdstn, and an existing
file is never replaced (use --force to allow it). --output replaces an
existing file. No option writes over the input file or into the folder of
the key database.`,
	Args: cobra.ExactArgs(1),
	RunE: runEncrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVar(&forEmail, "for", "", "encrypt for recipient (email)")
	encryptCmd.Flags().StringSliceVar(&recipientFlags, "recipient", nil, "encrypt for multiple recipients (repeatable, or comma-separated)")
	encryptCmd.Flags().StringArrayVar(&recipientKeyFlags, "recipient-key", nil, "encrypt for a raw X25519 public key: base64 of 32 bytes, or a file that holds it (repeatable)")
	encryptCmd.Flags().StringVar(&password, "password", "", "encrypt with a file password (keyless)")
	encryptCmd.Flags().StringVar(&passphrase, "passphrase", "", "encrypt with a file password (keyless)")
	encryptCmd.Flags().StringVar(&passwordFile, "password-file", "", "read the file password from a file, or - for stdin (one trailing newline removed)")
	encryptCmd.Flags().StringVar(&keyPassphraseFile, "key-passphrase-file", "", "read the passphrase for your default key from a file, or - for stdin")
	encryptCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path; replaces an existing file, except the input (default: <file>.mdstn, never replaces a file)")
	encryptCmd.Flags().BoolVar(&forceOverwrite, "force", false, "allow the default output path <file>.mdstn to replace an existing file")
	if err := encryptCmd.Flags().MarkHidden("passphrase"); err != nil {
		panic(err)
	}
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	flags := cmd.Flags()

	passwordSet := flags.Changed("password")
	passphraseSet := flags.Changed("passphrase")
	passwordFileSet := flags.Changed("password-file")
	if (passwordSet || passphraseSet) && passwordFileSet {
		return errors.New("--password and --password-file are mutually exclusive")
	}
	hasRecipients := flags.Changed("for") || flags.Changed("recipient") || flags.Changed("recipient-key")
	if hasRecipients && (passwordSet || passphraseSet || passwordFileSet) {
		return errors.New("recipient flags (--for, --recipient, --recipient-key) and a password flag are mutually exclusive")
	}
	if err := checkRecipientValues(flags.Changed("recipient"), recipientFlags, recipientKeyFlags); err != nil {
		return err
	}

	resolved, err := resolvePassword(password, passphrase, passwordSet, passphraseSet)
	if err != nil {
		return err
	}
	if passwordFileSet {
		if resolved, err = secretFromFile(passwordFile); err != nil {
			return fmt.Errorf("--password-file: %w", err)
		}
	}
	var keyPass string
	if flags.Changed("key-passphrase-file") {
		if keyPass, err = secretFromFile(keyPassphraseFile); err != nil {
			return fmt.Errorf("--key-passphrase-file: %w", err)
		}
	}

	// Validate raw keys before the database is opened or any output is written.
	rawRecipients, err := rawKeyRecipients(recipientKeyFlags)
	if err != nil {
		return err
	}

	ctx, stop := commandContext(cmd)
	defer stop()

	encryptCommand := NewEncryptCommand(dbPath, jsonOutput, verbose)
	return encryptCommand.Execute(ctx, encryptOptions{
		FilePath:       filePath,
		ForEmail:       forEmail,
		Password:       resolved,
		KeyPassphrase:  keyPass,
		OutputPath:     outputPath,
		RecipientFlags: recipientFlags,
		RawRecipients:  rawRecipients,
		Overwrite:      forceOverwrite,
	})
}

// checkRecipientValues rejects an empty recipient value: `--recipient ""`,
// an empty item in a --recipient comma list, and `--recipient-key ""`.
// recipientSet reports whether --recipient was given; pflag turns
// `--recipient ""` into no values.
func checkRecipientValues(recipientSet bool, recipients, recipientKeys []string) error {
	if recipientSet && len(recipients) == 0 {
		return errors.New("--recipient: a recipient value must not be empty")
	}
	for _, v := range recipients {
		for _, item := range strings.Split(v, ",") {
			if strings.TrimSpace(item) == "" {
				return fmt.Errorf("--recipient %q: a recipient value must not be empty", v)
			}
		}
	}
	for _, v := range recipientKeys {
		if strings.TrimSpace(v) == "" {
			return errors.New("--recipient-key: a recipient key must not be empty")
		}
	}
	return nil
}
