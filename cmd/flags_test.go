package cmd

import (
	"testing"
)

// TestResolvePassword covers the flag-resolution logic for --password / --passphrase.
func TestResolvePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		password      string
		passphrase    string
		passwordSet   bool
		passphraseSet bool
		want          string
		wantErr       bool
	}{
		{
			name:        "--password only resolves to that value",
			password:    "foo",
			passwordSet: true,
			want:        "foo",
		},
		{
			name:          "--passphrase only resolves (hidden alias works)",
			passphrase:    "foo",
			passphraseSet: true,
			want:          "foo",
		},
		{
			name:          "--password and --passphrase same value succeeds",
			password:      "foo",
			passphrase:    "foo",
			passwordSet:   true,
			passphraseSet: true,
			want:          "foo",
		},
		{
			name:          "--password and --passphrase different values returns error",
			password:      "foo",
			passphrase:    "bar",
			passwordSet:   true,
			passphraseSet: true,
			wantErr:       true,
		},
		{
			name: "neither flag set returns empty string",
			want: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolvePassword(tc.password, tc.passphrase, tc.passwordSet, tc.passphraseSet)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error but got nil (resolved %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolvePassword = %q; want %q", got, tc.want)
			}
		})
	}
}
