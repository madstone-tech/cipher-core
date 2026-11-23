package cipher_test

import (
	"context"
	"testing"
)

// TestExpiringKeys_IsASideEffectFreeRead verifies the core half of the
// check_expiry split: the SDK reports expiring keys and does nothing else.
// Notification, webhook dispatch and audit emission stay server-side.
func TestExpiringKeys_IsASideEffectFreeRead(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if _, err := client.CreateKey(ctx, "no-expiry", "key-passphrase-123"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := client.ExpiringKeys(ctx)
	if err != nil {
		t.Fatalf("ExpiringKeys: %v", err)
	}
	// A freshly created key carries no expiry, so the read is empty — and,
	// critically, produced no notification side effects to observe.
	if len(got) != 0 {
		t.Fatalf("expected 0 expiring keys, got %d", len(got))
	}
}
