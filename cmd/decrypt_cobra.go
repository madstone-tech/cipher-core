package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt <file>",
	Short: "Decrypt a .mdstn file",
	Long: `Decrypt a .mdstn encrypted file.

The decryption method is automatically detected from the file header.
For password-encrypted files, you will be prompted for the file password.

Output: without --output, the plaintext goes to the input path without
.mdstn (else the input path plus .decrypted), and an existing file is never
replaced (use --force to allow it). The sender's file name in the header is
only shown, never used as a path. --output replaces an existing file. No
option writes over the input file or into the folder of the key database.

Examples:
  $ mdstn-cipher decrypt secret.pdf.mdstn
  $ mdstn-cipher decrypt secret.pdf.mdstn --output decrypted.pdf
  $ mdstn-cipher decrypt secret.pdf.mdstn --password mypassword
  $ mdstn-cipher decrypt secret.pdf.mdstn --password-file pw.txt
  $ mdstn-cipher decrypt secret.pdf.mdstn --key-passphrase-file - < key-pass.txt`,
	Args: cobra.ExactArgs(1),
	RunE: runDecrypt,
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVar(&password, "password", "", "file password for a keyless file")
	decryptCmd.Flags().StringVar(&passphrase, "passphrase", "", "file password for a keyless file")
	decryptCmd.Flags().StringVar(&passwordFile, "password-file", "", "read the file password from a file, or - for stdin (one trailing newline removed)")
	decryptCmd.Flags().StringVar(&keyPassphraseFile, "key-passphrase-file", "", "read the key passphrase (or recovery phrase) from a file, or - for stdin")
	decryptCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path; replaces an existing file, except the input (default: the input path without .mdstn, never replaces a file)")
	decryptCmd.Flags().BoolVar(&forceOverwrite, "force", false, "allow the default output path to replace an existing file")
	if err := decryptCmd.Flags().MarkHidden("passphrase"); err != nil {
		panic(err)
	}
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	flags := cmd.Flags()

	passwordSet := flags.Changed("password")
	passphraseSet := flags.Changed("passphrase")
	passwordFileSet := flags.Changed("password-file")
	keyPassFileSet := flags.Changed("key-passphrase-file")
	if (passwordSet || passphraseSet) && passwordFileSet {
		return errors.New("--password and --password-file are mutually exclusive")
	}
	if passwordFileSet && keyPassFileSet && passwordFile == stdinPath && keyPassphraseFile == stdinPath {
		return errors.New("--password-file and --key-passphrase-file cannot both read stdin")
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
	if keyPassFileSet {
		if keyPass, err = secretFromFile(keyPassphraseFile); err != nil {
			return fmt.Errorf("--key-passphrase-file: %w", err)
		}
	}

	ctx, stop := commandContext(cmd)
	defer stop()

	decryptCommand := NewDecryptCommand(dbPath, jsonOutput, verbose)
	return decryptCommand.Execute(ctx, filePath, resolved, keyPass, outputPath, forceOverwrite)
}
