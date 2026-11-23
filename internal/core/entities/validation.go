package entities

import (
	"errors"
	"strings"
)

var (
	errEmailEmpty  = errors.New("email must not be empty")
	errEmailNoAt   = errors.New("email must contain '@'")
	errSlugEmpty   = errors.New("slug must not be empty")
	errSlugInvalid = errors.New("slug must contain only lowercase letters, digits, and hyphens")
)

// ValidateEmail returns a non-nil error if email is empty or missing "@".
func ValidateEmail(email string) error {
	if strings.TrimSpace(email) == "" {
		return errEmailEmpty
	}
	if !strings.Contains(email, "@") {
		return errEmailNoAt
	}
	return nil
}

// ValidateSlug returns a non-nil error if slug is empty or contains characters
// outside [a-z0-9-].
func ValidateSlug(slug string) error {
	if slug == "" {
		return errSlugEmpty
	}
	for _, c := range slug {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return errSlugInvalid
		}
	}
	return nil
}
