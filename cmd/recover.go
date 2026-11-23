package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// RecoverCommand handles key recovery operations.
type RecoverCommand struct {
	dbPath string
}

// NewRecoverCommand creates a new RecoverCommand.
func NewRecoverCommand(dbPath string) *RecoverCommand {
	return &RecoverCommand{dbPath: dbPath}
}

// ExecuteFromMnemonic recovers a key from a BIP39 mnemonic.
func (c *RecoverCommand) ExecuteFromMnemonic(ctx context.Context) (retErr error) {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close database: %w", cerr))
		}
	}()

	prompter := cli.NewPrompter()

	recoverUC := usecases.NewRecoverKey(
		adapters.KEKProvider,
		adapters.KeyRepo,
		adapters.CryptoEngine,
		prompter,
		adapters.Logger,
	)

	key, err := recoverUC.RecoverFromMnemonic(ctx, crypto.DeriveX25519FromMnemonic)
	if err != nil {
		return err
	}

	fmt.Printf("Key stored (fingerprint: %s...) — use 'cipher keys list' to confirm.\n", key.Fingerprint[:8])
	return nil
}
