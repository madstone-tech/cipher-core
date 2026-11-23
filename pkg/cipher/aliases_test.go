package cipher_test

import (
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// These compile only if the aliases exist, and they pin the sentinels to the
// same values the repositories return — an alias that pointed at a fresh
// errors.New would break errors.Is at every call site silently. Identity
// (==) against the source sentinel is the only check that proves that: a
// copy would still satisfy errors.Is(err, err) trivially for any non-nil
// error, so that self-comparison asserts nothing.
func TestCoreTypeAliasesExist(t *testing.T) {
	var (
		_ *cipher.IdentityKey
		_ *cipher.SharedKeyPolicy
		_ *cipher.SharedKeyGrant
		_ cipher.GrantStatus
	)

	cases := []struct {
		name   string
		alias  error
		source error
	}{
		{"ErrNotFound", cipher.ErrNotFound, entities.ErrNotFound},
		{"ErrAlreadyExists", cipher.ErrAlreadyExists, entities.ErrAlreadyExists},
		{"ErrInvalidInput", cipher.ErrInvalidInput, entities.ErrInvalidInput},
		{"ErrUnauthorized", cipher.ErrUnauthorized, entities.ErrUnauthorized},
	}

	for _, tc := range cases {
		if tc.alias == nil {
			t.Errorf("%s is nil", tc.name)
			continue
		}
		if tc.alias != tc.source {
			t.Errorf("%s is not identical to entities.%s; alias is a copy and would break errors.Is at call sites", tc.name, tc.name)
		}
	}
}
