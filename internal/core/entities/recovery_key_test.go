package entities

import (
	"testing"
	"time"
)

func TestRecoveryKey_Validate(t *testing.T) {
	validSalt := make([]byte, 16)
	validTime := time.Now()

	tests := []struct {
		name    string
		rk      RecoveryKey
		wantErr bool
	}{
		{
			name:    "valid key passes",
			rk:      RecoveryKey{ID: "abc123", Salt: validSalt, CreatedAt: validTime},
			wantErr: false,
		},
		{
			name:    "empty ID fails",
			rk:      RecoveryKey{ID: "", Salt: validSalt, CreatedAt: validTime},
			wantErr: true,
		},
		{
			name:    "salt too short fails",
			rk:      RecoveryKey{ID: "abc123", Salt: make([]byte, 8), CreatedAt: validTime},
			wantErr: true,
		},
		{
			name:    "salt too long fails",
			rk:      RecoveryKey{ID: "abc123", Salt: make([]byte, 32), CreatedAt: validTime},
			wantErr: true,
		},
		{
			name:    "nil salt fails",
			rk:      RecoveryKey{ID: "abc123", Salt: nil, CreatedAt: validTime},
			wantErr: true,
		},
		{
			name:    "zero CreatedAt fails",
			rk:      RecoveryKey{ID: "abc123", Salt: validSalt, CreatedAt: time.Time{}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rk.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}
