package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseExpiryDuration parses a human-friendly duration string into a
// time.Duration. It extends time.ParseDuration to accept day and week
// suffixes:
//
//	Nd  — N days   (e.g. "30d" → 30 * 24 * time.Hour)
//	Nw  — N weeks  (e.g. "4w"  →  4 * 7 * 24 * time.Hour)
//
// All other values are forwarded to time.ParseDuration (e.g. "720h", "90m").
func ParseExpiryDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Handle day suffix.
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid day duration %q: must be a positive integer followed by 'd'", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	// Handle week suffix.
	if strings.HasSuffix(s, "w") {
		n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid week duration %q: must be a positive integer followed by 'w'", s)
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}

	// Fall back to standard Go duration parsing (h, m, s, ms, us, ns).
	return time.ParseDuration(s)
}
