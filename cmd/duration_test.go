package cmd_test

import (
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/cmd"
)

func TestParseExpiryDuration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		// Day suffix
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"90d", 90 * 24 * time.Hour, false},

		// Week suffix
		{"1w", 7 * 24 * time.Hour, false},
		{"4w", 28 * 24 * time.Hour, false},
		{"52w", 364 * 24 * time.Hour, false},

		// Standard Go durations
		{"720h", 720 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"90m", 90 * time.Minute, false},

		// Errors
		{"0d", 0, true},
		{"-1d", 0, true},
		{"0w", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"1.5d", 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := cmd.ParseExpiryDuration(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseExpiryDuration(%q): want error, got nil (duration %v)", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseExpiryDuration(%q): unexpected error: %v", tc.input, err)
				return
			}
			if got != tc.want {
				t.Errorf("ParseExpiryDuration(%q): want %v, got %v", tc.input, tc.want, got)
			}
		})
	}
}
