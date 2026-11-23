package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// CheckExpiryCommand is the CLI executor for the one-shot expiry check.
//
// This command reads through pkg/cipher.ExpiringKeys — a pure,
// side-effect-free read — instead of performing notification dispatch itself.
// It writes no expiry-notification dedup records or audit rows locally;
// notification dispatch (webhooks, audit trail) is a commercial server feature
// outside this module, whose sweep is unchanged. This command remains
// detection + CLI output only.
type CheckExpiryCommand struct {
	dbPath string
}

// NewCheckExpiryCommand constructs a CheckExpiryCommand.
func NewCheckExpiryCommand(dbPath string) *CheckExpiryCommand {
	return &CheckExpiryCommand{dbPath: dbPath}
}

// Execute runs a single expiry sweep and prints a human-readable summary.
func (c *CheckExpiryCommand) Execute(ctx context.Context) error {
	client, err := cipher.NewLocal(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer client.Close() //nolint:errcheck // best-effort: read-only close (expiry sweep only reads keys)

	keys, err := client.ExpiringKeys(ctx)
	if err != nil {
		return fmt.Errorf("check expiry: %w", err)
	}

	now := time.Now().UTC()

	// Same thresholds as the server-side sweep (internal/server/usecases.CheckExpiryUseCase):
	// past ExpiresAt is "expired"; otherwise within 7 days (which subsumes the
	// urgent within-1-day case) is "expiring".
	var expiring, expired int
	for _, key := range keys {
		if key.ExpiresAt == nil {
			continue
		}
		expiresAt := key.ExpiresAt.UTC()
		switch {
		case now.After(expiresAt):
			expired++
		case expiresAt.Sub(now).Hours()/24 <= 7:
			expiring++
		}
	}

	fmt.Printf("Expiry check complete: %d expiring (within 7 days), %d expired\n", expiring, expired)
	if expiring == 0 && expired == 0 {
		fmt.Println("All keys are healthy.")
		return nil
	}

	for _, key := range keys {
		if key.ExpiresAt == nil {
			continue
		}
		expiresAt := key.ExpiresAt.UTC()
		status := "expiring"
		if now.After(expiresAt) {
			status = "expired"
		} else if expiresAt.Sub(now).Hours()/24 > 7 {
			continue
		}
		fmt.Printf("  %s: %s %s\n", key.Alias, status, expiresAt.Format(time.RFC3339))
	}

	fmt.Println("Run 'mdstn-cipher keys list' to see expiry annotations.")
	fmt.Println("Recommendation: " + expiryRecommendationMsg())
	return nil
}

// expiryRecommendationMsg returns the canonical recommendation string.
// Defined here to avoid an import cycle; mirrors the usecase constant.
func expiryRecommendationMsg() string {
	return "Create a new key and re-share with recipients"
}
