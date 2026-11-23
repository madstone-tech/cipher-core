package cmd

import "testing"

// TestRemovedCLICommands guards against re-introducing the local-only commands
// that could never function end-to-end on the single-user SQLite CLI:
//   - `share`   minted policies/grants in the local DB with no delivery channel.
//   - `api-key` minted credentials in the local DB that authenticate nothing
//     (REST auth validates against the server's PostgreSQL store).
func TestRemovedCLICommands(t *testing.T) {
	removed := map[string]bool{"share": true, "api-key": true}
	for _, c := range rootCmd.Commands() {
		if removed[c.Name()] {
			t.Errorf("command %q was removed but is still registered on rootCmd", c.Name())
		}
	}
}

// TestRecoverSubcommands verifies that `recover from-server` (which always failed
// because the CLI wires no key-backup service) is gone, while the working
// `recover from-mnemonic` flow remains.
func TestRecoverSubcommands(t *testing.T) {
	names := make(map[string]bool)
	for _, sub := range recoverCmd.Commands() {
		names[sub.Name()] = true
	}
	if names["from-server"] {
		t.Error("`recover from-server` was removed but is still registered")
	}
	if !names["from-mnemonic"] {
		t.Error("`recover from-mnemonic` must remain registered")
	}
}
