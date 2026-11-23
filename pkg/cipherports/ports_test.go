package cipherports_test

import (
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipherports"
)

// Compiles only if every alias exists. Declaring the variables is the whole
// assertion: these are interfaces, so a nil value of each is sufficient to
// prove the name resolves to an interface type.
func TestCorePortAliasesExist(t *testing.T) {
	var (
		_ cipherports.Logger
		_ cipherports.SessionStore
		_ cipherports.KEKProvider
		_ cipherports.IdentityKeyRepository
		_ cipherports.CryptoEngine
		_ cipherports.SharedKeyPolicyRepository
		_ cipherports.UserPrompter
		_ cipherports.PasswordVerifier
	)
}
