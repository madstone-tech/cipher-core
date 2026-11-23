package cipher

import "fmt"

// headlessPrompter adapts fixed SDK inputs to the usecases.UserPrompter
// port. The SDK never interacts with a terminal: every prompt resolves from
// the caller-supplied input or fails explicitly.
type headlessPrompter struct {
	// passphrase is the key passphrase supplied for wrap/unwrap operations.
	passphrase string
}

// PromptString returns the fixed passphrase for string prompts (used by
// recovery-phrase paths that the SDK replaces with direct input — those
// paths never call this; it exists to satisfy the interface).
func (p *headlessPrompter) PromptString(prompt string) (string, error) {
	return "", fmt.Errorf("cipher: sdk does not prompt: %s (supply the input directly)", prompt)
}

// PromptConfirm auto-confirms. Destructive operations in SDK mode are
// authorized by the caller calling them — confirmation is implicit.
func (p *headlessPrompter) PromptConfirm(string) (bool, error) { return true, nil }

// PromptPassphrase returns the caller-supplied key passphrase.
func (p *headlessPrompter) PromptPassphrase(string) (string, error) {
	if p.passphrase == "" {
		return "", fmt.Errorf("cipher: no key passphrase supplied — set EncryptInput.KeyPassphrase or DecryptInput.RecoveryPassphrase")
	}
	return p.passphrase, nil
}
