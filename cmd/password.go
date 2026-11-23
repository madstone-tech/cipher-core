package cmd

import "fmt"

// resolvePassword merges the primary --password flag with the legacy --passphrase
// alias and enforces the invariant that they must not differ when both are set.
//
// Rules:
//   - Only --password set: use it.
//   - Only --passphrase set: use it (backward-compatible alias).
//   - Both set to equal values: proceed with that value.
//   - Both set to different values: return an error.
//   - Neither set: return "" (callers may prompt interactively).
func resolvePassword(password, passphrase string, passwordSet, passphraseSet bool) (string, error) {
	switch {
	case passwordSet && passphraseSet:
		if password != passphrase {
			return "", fmt.Errorf("--passphrase is a deprecated alias for --password; do not set both to different values")
		}
		return password, nil
	case passwordSet:
		return password, nil
	case passphraseSet:
		return passphrase, nil
	default:
		return "", nil
	}
}
