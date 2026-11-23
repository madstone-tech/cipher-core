package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"strings"
	"time"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// encryptResult is the JSON output structure for the encrypt command.
type encryptResult struct {
	OutputPath              string `json:"output_path"`
	Method                  string `json:"method"`
	Fingerprint             string `json:"fingerprint"`
	RecoveryMnemonic        string `json:"recovery_mnemonic,omitempty"`
	RecoveryMnemonicWarning string `json:"recovery_mnemonic_warning,omitempty"`
}

const recoveryMnemonicWarning = "Store this phrase securely. It will not be shown again."

type EncryptCommand struct {
	dbPath     string
	jsonOutput bool
	verbose    bool
}

func NewEncryptCommand(dbPath string, jsonOutput bool, verbose bool) *EncryptCommand {
	return &EncryptCommand{
		dbPath:     dbPath,
		jsonOutput: jsonOutput,
		verbose:    verbose,
	}
}

// encryptOptions are the inputs of one encrypt run.
type encryptOptions struct {
	FilePath       string
	ForEmail       string
	Password       string // file password (method 3)
	KeyPassphrase  string // passphrase for a new default key (encrypt for self)
	OutputPath     string
	RecipientFlags []string             // --recipient values, resolved via CKD or the local store
	RawRecipients  []usecases.Recipient // validated --recipient-key values
	Overwrite      bool                 // --force: the default <file>.mdstn may replace a file
}

func (c *EncryptCommand) Execute(ctx context.Context, opts encryptOptions) (err error) {
	// Encrypt opens the concrete *sqlite.KeyRepository directly (rather than
	// via NewCommonAdapters) because CKD wiring requires keyRepo.DB() — a
	// method on the concrete type that is intentionally absent from the
	// usecases.KeyRepository port interface.
	keyRepo, err := sqlite.NewIdentityKeyRepository(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := keyRepo.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close database: %w", cerr)
		}
	}()

	cryptoEngine := crypto.NewEngine()
	encoder := crypto.NewFileEncoder()

	// Create CKD cache and client
	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	ckdClient := ckd.NewClient(ckdCache)

	// Create recovery key repository sharing the same DB connection.
	recoveryRepo := sqlite.NewRecoveryKeyRepository(keyRepo.DB())

	fileHandler := cli.NewFileHandler()
	progress := cli.NewCommandProgress(c.jsonOutput)
	prompter := newCLIPrompter(ctx, opts.KeyPassphrase)
	logger := logging.NewSimpleLogger()

	// LookupKey usecase owns the cache-check → network-fetch → cache-write chain
	lookupKeyUC := usecases.NewLookupKey(ckdClient, ckdCache, logger)

	// Create usecase
	kekProvider := crypto.NewArgon2idKEKProvider()
	sessionStore := crypto.NewInMemorySessionStore(ctx)
	defer sessionStore.Stop()

	encryptUC := usecases.NewEncryptFile(
		keyRepo,
		recoveryRepo,
		cryptoEngine,
		kekProvider,
		sessionStore,
		encoder,
		lookupKeyUC,
		fileHandler,
		progress,
		prompter,
		logger,
	).ProtectKeyStore(protectedKeyStores(c.dbPath)...)

	// Check the output path before any CKD lookup, prompt, or KDF (T-7).
	if _, _, err := encryptUC.CheckOutput(&usecases.EncryptFileRequest{
		FilePath: opts.FilePath, OutputPath: opts.OutputPath, Overwrite: opts.Overwrite,
	}); err != nil {
		return withOutputHint(err)
	}

	// Resolve recipients first: with any recipient, there is no file password.
	recipients, err := c.resolveRecipients(ctx, keyRepo, lookupKeyUC, opts.RecipientFlags)
	if err != nil {
		return err
	}
	recipients = append(recipients, opts.RawRecipients...)

	// Prompt for a file password only when nothing else selects the method.
	// --key-passphrase-file selects encrypt for self.
	password := opts.Password
	if password == "" && opts.ForEmail == "" && len(recipients) == 0 && opts.KeyPassphrase == "" {
		password, err = prompter.PromptPassphrase("Enter file password: ")
		if err != nil {
			return fmt.Errorf("failed to read file password: %w", err)
		}
	}

	resp, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:       opts.FilePath,
		RecipientEmail: opts.ForEmail,
		Recipients:     recipients,
		Passphrase:     password,
		OutputPath:     opts.OutputPath,
		Overwrite:      opts.Overwrite,
		JSONOutput:     c.jsonOutput,
	})
	if err != nil {
		if errors.Is(err, entities.ErrRecoveryAborted) {
			fmt.Fprintln(os.Stderr, "⚠ Recovery phrase not confirmed. Re-run to complete setup.")
		}
		return withOutputHint(err)
	}

	// Non-blocking expiry warning: if the key used is expiring within 7 days,
	// print a warning so the user knows to rotate it. The encryption already
	// succeeded — this is advisory only.
	if resp.Fingerprint != "" {
		if key, lookErr := keyRepo.GetByFingerprint(ctx, resp.Fingerprint); lookErr == nil {
			warnKeyExpiry(key)
		}
	}

	// Output result
	if c.jsonOutput {
		result := encryptResult{
			OutputPath:  resp.OutputPath,
			Method:      string(resp.Method),
			Fingerprint: resp.Fingerprint,
		}
		if resp.RecoveryMnemonic != "" {
			result.RecoveryMnemonic = resp.RecoveryMnemonic
			result.RecoveryMnemonicWarning = recoveryMnemonicWarning
		}
		out, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("\nEncrypted file: %s\n", resp.OutputPath)
		fmt.Printf("Method: %s\n", resp.Method)
		if resp.Fingerprint != "" {
			fmt.Printf("Fingerprint: %s\n", resp.Fingerprint)
		}
	}

	return nil
}

// warnKeyExpiry prints a non-blocking warning to stderr if the given key is
// expiring within 7 days (or is already expired). The encryption still succeeds.
func warnKeyExpiry(key *entities.IdentityKey) {
	if key.ExpiresAt == nil {
		return
	}
	if key.IsExpired() {
		fmt.Fprintln(os.Stderr, ansiRed+"⚠ Warning: the key used for this encryption has expired. Create a new key and re-encrypt."+ansiReset)
		return
	}
	daysLeft := time.Until(*key.ExpiresAt)
	days := int(math.Ceil(daysLeft.Hours() / 24))
	if days <= 7 {
		fmt.Fprintf(os.Stderr, ansiYellow+"⚠ Warning: the key used for this encryption expires in %d day(s) (%s). Recommendation: create a new key and re-share with recipients.\n"+ansiReset,
			days, key.ExpiresAt.Format("2006-01-02"))
	}
}

// resolveRecipients converts CLI recipient strings (emails, key IDs, fingerprints)
// into a slice of usecases.Recipient. Each string is resolved via CKD lookup or
// local key repository lookup.
func (c *EncryptCommand) resolveRecipients(ctx context.Context, keyRepo *sqlite.IdentityKeyRepository, lookupKeyUC *usecases.LookupKey, flags []string) ([]usecases.Recipient, error) {
	if len(flags) == 0 {
		return nil, nil
	}

	var recipients []usecases.Recipient
	for _, flag := range flags {
		// Split comma-separated values
		for _, item := range strings.Split(flag, ",") {
			item = strings.TrimSpace(item)

			// Try CKD lookup by email (contains @)
			if strings.Contains(item, "@") {
				lookupResp, err := lookupKeyUC.Execute(ctx, &usecases.LookupKeyRequest{Email: item})
				if err != nil {
					return nil, fmt.Errorf("CKD lookup failed for %s: %w", item, err)
				}
				recipients = append(recipients, usecases.Recipient{
					PublicKey:   lookupResp.PublicKey,
					Fingerprint: lookupResp.Fingerprint,
				})
				continue
			}

			// Try local key lookup by ID or fingerprint
			key, err := keyRepo.GetByID(ctx, item)
			if err != nil {
				key, err = keyRepo.GetByFingerprint(ctx, item)
			}
			if err != nil {
				return nil, fmt.Errorf("no key found for recipient %q (try email or key ID)", item)
			}
			recipients = append(recipients, usecases.Recipient{
				PublicKey:   key.PublicKey,
				Fingerprint: key.Fingerprint,
			})
		}
	}

	return recipients, nil
}

// withOutputHint adds the CLI hint to an "output exists" error.
func withOutputHint(err error) error {
	if errors.Is(err, entities.ErrAlreadyExists) || errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w\nchoose another path with -o, or replace the file with --force", err)
	}
	return err
}
