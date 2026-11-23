package entities

import "time"

// RecoveryKey stores the Argon2id salt derived from a BIP39 mnemonic.
// The mnemonic itself is never persisted.
type RecoveryKey struct {
	ID        string // SHA-256(salt)[:16] hex
	Salt      []byte // 16-byte Argon2id salt
	CreatedAt time.Time
}

// Validate validates the RecoveryKey fields.
func (r *RecoveryKey) Validate() error {
	if r.ID == "" {
		return ErrInvalidInput
	}
	if len(r.Salt) != 16 {
		return ErrInvalidInput
	}
	if r.CreatedAt.IsZero() {
		return ErrInvalidInput
	}
	return nil
}
