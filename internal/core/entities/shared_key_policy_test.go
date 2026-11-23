package entities

import (
	"testing"
	"time"
)

func TestSharedKeyPolicy_Validate(t *testing.T) {
	valid := SharedKeyPolicy{
		ID:        "pol-1",
		Name:      "Project Alpha",
		OwnerID:   "user-1",
		KeyHash:   "sha256hash",
		CreatedAt: time.Now(),
		IsActive:  true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid policy should pass: %v", err)
	}
}

func TestSharedKeyPolicy_Validate_MissingName(t *testing.T) {
	p := SharedKeyPolicy{ID: "pol-2", OwnerID: "user-1", KeyHash: "h", CreatedAt: time.Now(), IsActive: true}
	if err := p.Validate(); err == nil {
		t.Fatal("missing Name should fail")
	}
}

func TestSharedKeyPolicy_Validate_MissingOwnerID(t *testing.T) {
	p := SharedKeyPolicy{ID: "pol-3", Name: "X", KeyHash: "h", CreatedAt: time.Now(), IsActive: true}
	if err := p.Validate(); err == nil {
		t.Fatal("missing OwnerID should fail")
	}
}

func TestSharedKeyPolicy_Validate_MissingKeyHash(t *testing.T) {
	p := SharedKeyPolicy{ID: "pol-4", Name: "X", OwnerID: "u", CreatedAt: time.Now(), IsActive: true}
	if err := p.Validate(); err == nil {
		t.Fatal("missing KeyHash should fail")
	}
}

func TestSharedKeyPolicy_Validate_RevokedButActive(t *testing.T) {
	now := time.Now()
	p := SharedKeyPolicy{
		ID: "pol-5", Name: "X", OwnerID: "u", KeyHash: "h",
		CreatedAt: now, RevokedAt: &now, IsActive: true,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("revoked policy that is active should fail")
	}
}

func TestSharedKeyGrant_Validate(t *testing.T) {
	valid := SharedKeyGrant{
		ID:                "grant-1",
		PolicyID:          "pol-1",
		GranteeID:         "user-2",
		EncryptedKeyBytes: []byte("encrypted"),
		GrantedAt:         time.Now(),
		Status:            GrantStatusActive,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid grant should pass: %v", err)
	}
}

func TestSharedKeyGrant_Validate_MissingEncryptedKeyBytes(t *testing.T) {
	g := SharedKeyGrant{
		ID: "grant-2", PolicyID: "pol-1", GranteeID: "user-2",
		GrantedAt: time.Now(), Status: GrantStatusActive,
	}
	if err := g.Validate(); err == nil {
		t.Fatal("missing EncryptedKeyBytes should fail")
	}
}

func TestSharedKeyGrant_Validate_InvalidStatus(t *testing.T) {
	g := SharedKeyGrant{
		ID: "grant-3", PolicyID: "pol-1", GranteeID: "user-2",
		EncryptedKeyBytes: []byte("x"), GrantedAt: time.Now(), Status: "unknown",
	}
	if err := g.Validate(); err == nil {
		t.Fatal("invalid status should fail")
	}
}
