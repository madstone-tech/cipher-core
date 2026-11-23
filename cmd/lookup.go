package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// LookupCommand handles CKD public key lookups.
type LookupCommand struct {
	dbPath string
}

// NewLookupCommand creates a new LookupCommand.
func NewLookupCommand(dbPath string) *LookupCommand {
	return &LookupCommand{dbPath: dbPath}
}

// Execute looks up a public key by email via CKD.
func (c *LookupCommand) Execute(ctx context.Context, email string, save, jsonOutput bool) (retErr error) {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close database: %w", cerr))
		}
	}()

	lookupUC := usecases.NewLookupKey(adapters.CKDClient, adapters.CKDCacheRepo, adapters.Logger)
	result, err := lookupUC.Execute(ctx, &usecases.LookupKeyRequest{Email: email})
	if err != nil {
		return fmt.Errorf("key lookup failed for %s: %w", email, err)
	}

	fingerprint := formatFingerprint(result.Fingerprint)
	source := "network"
	if result.FromCache {
		source = "cache"
	}

	if jsonOutput {
		info := map[string]string{
			"email":       email,
			"fingerprint": result.Fingerprint,
			"keyType":     "x25519",
			"source":      source,
		}
		if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
			return fmt.Errorf("failed to write lookup JSON: %w", err)
		}
		return nil
	}

	fmt.Printf("%s\n", email)
	fmt.Printf("Key found: x25519\n")
	fmt.Printf("Fingerprint: %s\n", fingerprint)
	fmt.Printf("Source: %s\n", source)

	if result.FromCache {
		fmt.Println("Trust: cached (previously verified)")
	} else {
		fmt.Println("Trust: TOFU (first lookup — fingerprint recorded)")
	}

	return nil
}

// formatFingerprint formats a hex fingerprint as groups of 4 uppercase chars.
func formatFingerprint(fp string) string {
	fp = strings.ToUpper(fp)
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}
	return strings.Join(parts, "-")
}
