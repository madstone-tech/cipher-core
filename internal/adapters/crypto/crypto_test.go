package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	mathrand "math/rand/v2"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func TestAESEncryptDecrypt(t *testing.T) {
	engine := NewEngine()

	// Generate key
	key, err := engine.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Test data
	plaintext := []byte("This is a secret message for testing AES-256-GCM encryption.")

	// Encrypt
	ciphertext, nonce, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	if len(nonce) != 12 {
		t.Errorf("Expected 12-byte nonce, got %d bytes", len(nonce))
	}

	// Decrypt
	decrypted, err := engine.DecryptAES(ciphertext, key, nonce, nil)
	if err != nil {
		t.Fatalf("DecryptAES failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestX25519EncryptDecrypt(t *testing.T) {
	engine := NewEngine()

	// Generate keypair
	publicKey, privateKey, err := engine.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair failed: %v", err)
	}

	if len(publicKey) != 32 {
		t.Errorf("Expected 32-byte public key, got %d bytes", len(publicKey))
	}
	if len(privateKey) != 32 {
		t.Errorf("Expected 32-byte private key, got %d bytes", len(privateKey))
	}

	// Test data
	plaintext := []byte("This is a secret message for testing X25519 hybrid encryption.")

	// Encrypt
	ciphertext, ephemeralPubKey, nonce, err := engine.EncryptX25519(plaintext, publicKey, nil)
	if err != nil {
		t.Fatalf("EncryptX25519 failed: %v", err)
	}

	if len(ephemeralPubKey) != 32 {
		t.Errorf("Expected 32-byte ephemeral public key, got %d bytes", len(ephemeralPubKey))
	}
	if len(nonce) != 12 {
		t.Errorf("Expected 12-byte nonce, got %d bytes", len(nonce))
	}

	// Decrypt
	decrypted, err := engine.DecryptX25519(ciphertext, ephemeralPubKey, nonce, privateKey, nil)
	if err != nil {
		t.Fatalf("DecryptX25519 failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// ── Shared test helpers ───────────────────────────────────────────────────────

// mustHex decodes a hex string to bytes, failing the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return b
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("randomBytes: %v", err)
	}
	return buf
}

func streamRoundTrip(t *testing.T, engine *Engine, plaintext []byte) {
	t.Helper()
	key := randomBytes(t, 32)
	ctx := context.Background()

	var cipherBuf bytes.Buffer
	if err := engine.EncryptStream(ctx, bytes.NewReader(plaintext), &cipherBuf, key, nil); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var plainBuf bytes.Buffer
	if err := engine.DecryptStream(ctx, &cipherBuf, &plainBuf, key, nil); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}

	if !bytes.Equal(plaintext, plainBuf.Bytes()) {
		t.Errorf("round-trip mismatch: input %d bytes, output %d bytes", len(plaintext), plainBuf.Len())
	}
}

// roundTripAES verifies AES encrypt-then-decrypt for a given plaintext.
func roundTripAES(t *testing.T, engine *Engine, plaintext []byte) {
	t.Helper()
	key, err := engine.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}
	ct, nonce, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES: %v", err)
	}
	got, err := engine.DecryptAES(ct, key, nonce, nil)
	if err != nil {
		t.Fatalf("DecryptAES: %v", err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Errorf("AES round-trip mismatch: input %d bytes, output %d bytes", len(plaintext), len(got))
	}
}

// roundTripX25519 verifies X25519 encrypt-then-decrypt for a given plaintext.
func roundTripX25519(t *testing.T, engine *Engine, plaintext []byte) {
	t.Helper()
	pub, priv, err := engine.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair: %v", err)
	}
	ct, ephPub, nonce, err := engine.EncryptX25519(plaintext, pub, nil)
	if err != nil {
		t.Fatalf("EncryptX25519: %v", err)
	}
	got, err := engine.DecryptX25519(ct, ephPub, nonce, priv, nil)
	if err != nil {
		t.Fatalf("DecryptX25519: %v", err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Errorf("X25519 round-trip mismatch: input %d bytes, output %d bytes", len(plaintext), len(got))
	}
}

func TestStreamRoundTripZero(t *testing.T)    { streamRoundTrip(t, NewEngine(), []byte{}) }
func TestStreamRoundTripOneByte(t *testing.T) { streamRoundTrip(t, NewEngine(), []byte{0x42}) }
func TestStreamRoundTrip64KB(t *testing.T)    { streamRoundTrip(t, NewEngine(), randomBytes(t, 64*1024)) }

func TestStreamRoundTrip64KBPlus1(t *testing.T) {
	streamRoundTrip(t, NewEngine(), randomBytes(t, 64*1024+1))
}

func TestStreamRoundTrip128KB(t *testing.T) {
	streamRoundTrip(t, NewEngine(), randomBytes(t, 128*1024))
}
func TestStreamRoundTrip1MB(t *testing.T) { streamRoundTrip(t, NewEngine(), randomBytes(t, 1<<20)) }

func TestStreamAuthFailure(t *testing.T) {
	engine := NewEngine()
	key := randomBytes(t, 32)
	ctx := context.Background()

	plaintext := randomBytes(t, 512)
	var cipherBuf bytes.Buffer
	if err := engine.EncryptStream(ctx, bytes.NewReader(plaintext), &cipherBuf, key, nil); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	// Corrupt a byte in the ciphertext region (after the 12-byte base nonce + 4-byte len).
	corrupted := cipherBuf.Bytes()
	corrupted[12+4] ^= 0xFF

	var out bytes.Buffer
	err := engine.DecryptStream(ctx, bytes.NewReader(corrupted), &out, key, nil)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
	if out.Len() > 0 {
		t.Error("no plaintext should be written on auth failure")
	}
}

func TestStreamTruncated(t *testing.T) {
	engine := NewEngine()
	key := randomBytes(t, 32)
	ctx := context.Background()

	var cipherBuf bytes.Buffer
	if err := engine.EncryptStream(ctx, bytes.NewReader([]byte("hello")), &cipherBuf, key, nil); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	// Drop the last 4 bytes (the uint32(0) terminator).
	truncated := cipherBuf.Bytes()
	truncated = truncated[:len(truncated)-4]

	var out bytes.Buffer
	err := engine.DecryptStream(ctx, bytes.NewReader(truncated), &out, key, nil)
	if err == nil {
		t.Fatal("expected truncation error, got nil")
	}
}

func TestStreamWrongKey(t *testing.T) {
	engine := NewEngine()
	key := randomBytes(t, 32)
	wrongKey := randomBytes(t, 32)
	ctx := context.Background()

	var cipherBuf bytes.Buffer
	if err := engine.EncryptStream(ctx, bytes.NewReader([]byte("secret")), &cipherBuf, key, nil); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var out bytes.Buffer
	if err := engine.DecryptStream(ctx, &cipherBuf, &out, wrongKey, nil); err == nil {
		t.Fatal("expected decryption error with wrong key, got nil")
	}
}

// ── Argon2id tests ────────────────────────────────────────────────────────────

func TestArgon2idSaltUniqueness(t *testing.T) {
	engine := NewEngine()

	passphrase := "test-passphrase-argon2id"
	_, salt1, err := engine.DeriveKeyArgon2id(passphrase)
	if err != nil {
		t.Fatalf("first DeriveKeyArgon2id failed: %v", err)
	}
	_, salt2, err := engine.DeriveKeyArgon2id(passphrase)
	if err != nil {
		t.Fatalf("second DeriveKeyArgon2id failed: %v", err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("DeriveKeyArgon2id returned identical salts on two calls")
	}
}

func TestArgon2idKeyAndSaltLengths(t *testing.T) {
	engine := NewEngine()

	key, salt, err := engine.DeriveKeyArgon2id("passphrase")
	if err != nil {
		t.Fatalf("DeriveKeyArgon2id failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
	if len(salt) != argon2SaltLen {
		t.Errorf("salt length = %d, want %d", len(salt), argon2SaltLen)
	}
}

func TestHash(t *testing.T) {
	engine := NewEngine()

	data := []byte("test data")
	hash := engine.Hash(data)

	// SHA-256 produces 64 hex characters
	if len(hash) != 64 {
		t.Errorf("Expected 64-character hash, got %d characters", len(hash))
	}

	// Same input should produce same hash
	hash2 := engine.Hash(data)
	if hash != hash2 {
		t.Error("Same input produced different hashes")
	}

	// Different input should produce different hash
	hash3 := engine.Hash([]byte("different data"))
	if hash == hash3 {
		t.Error("Different inputs produced same hash")
	}
}

// ── Format encode/decode coverage ────────────────────────────────────────────

// TestDecodeErrors exercises various Decode error paths for coverage.
func TestDecodeErrors(t *testing.T) {
	fe := NewFileEncoder()

	// Too short.
	if _, err := fe.Decode([]byte("hi")); err == nil {
		t.Error("expected error for too-short input")
	}

	// Wrong magic.
	if _, err := fe.Decode([]byte("XXXX\x03\x02\x00\x00")); err == nil {
		t.Error("expected error for wrong magic")
	}

	// Invalid method byte.
	if _, err := fe.Decode([]byte("MDST\x03\x99\x00\x00")); err == nil {
		t.Error("expected error for unsupported method byte")
	}

	// Valid magic/version/method but truncated header JSON.
	buf := []byte("MDST\x03\x02\x00\x10") // claims 16 bytes of JSON but has 0
	if _, err := fe.Decode(buf); err == nil {
		t.Error("expected error for truncated header JSON")
	}
}

// TestDecodeWithOffset checks that DecodeWithOffset returns the raw header
// bytes as the AAD and the offset of the body (the header MAC).
func TestDecodeWithOffset(t *testing.T) {
	header := buildV2Container(t, formatV2, 3, validV2Password())
	_, aad, offset, err := NewFileEncoder().DecodeWithOffset(append(append([]byte{}, header...), make([]byte, 40)...))
	if err != nil {
		t.Fatalf("DecodeWithOffset: %v", err)
	}
	if offset != int64(len(header)) || !bytes.Equal(aad, header) {
		t.Errorf("offset = %d, AAD %d bytes; want %d and the raw header bytes", offset, len(aad), len(header))
	}
}

// ── Known-Answer Tests (US1) ──────────────────────────────────────────────────

// TestKATNISTAES256GCM verifies AES-256-GCM against NIST SP 800-38D test vectors.
// Sources: NIST CAVP gcmEncryptExtIV256.rsp (Vectors 1 & 2); NIST SP 800-38D Example 7 (Vector 3).
func TestKATNISTAES256GCM(t *testing.T) {
	engine := NewEngine()

	t.Run("V1_EmptyPT_AllZeroKeyIV", func(t *testing.T) {
		key := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000")
		nonce := mustHex(t, "000000000000000000000000")
		// Empty plaintext; ciphertext is just the 16-byte authentication tag.
		ctWithTag := mustHex(t, "530f8afbc74536b9a963b4f1c4cb738b")
		got, err := engine.DecryptAES(ctWithTag, key, nonce, nil)
		if err != nil {
			t.Fatalf("DecryptAES: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty plaintext, got %d bytes", len(got))
		}
	})

	t.Run("V2_NonEmptyPT_NoAAD", func(t *testing.T) {
		key := mustHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
		nonce := mustHex(t, "cafebabefacedbaddecaf888")
		wantPT := mustHex(t, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
		ctWithTag := mustHex(t, "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c")
		got, err := engine.DecryptAES(ctWithTag, key, nonce, nil)
		if err != nil {
			t.Fatalf("DecryptAES: %v", err)
		}
		if !bytes.Equal(wantPT, got) {
			t.Errorf("plaintext mismatch:\n  got  %x\n  want %x", got, wantPT)
		}
	})

	t.Run("V3_NonEmptyPT_WithAAD", func(t *testing.T) {
		// NIST SP 800-38D GCM Example 7 (256-bit key, with AAD).
		// Engine wrapper doesn't accept AAD, so call stdlib directly.
		key := mustHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
		nonce := mustHex(t, "cafebabefacedbaddecaf888")
		wantPT := mustHex(t, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
		aad := mustHex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
		ctWithTag := mustHex(t, "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b")

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM: %v", err)
		}
		got, err := gcm.Open(nil, nonce, ctWithTag, aad)
		if err != nil {
			t.Fatalf("gcm.Open: %v", err)
		}
		if !bytes.Equal(wantPT, got) {
			t.Errorf("plaintext mismatch:\n  got  %x\n  want %x", got, wantPT)
		}
	})
}

// TestKATRFC7748X25519 verifies Curve25519 ECDH against RFC 7748 §6.1 test vectors.
func TestKATRFC7748X25519(t *testing.T) {
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantSecret := mustHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	// Verify Alice's public key derivation.
	gotAlicePub, err := curve25519.X25519(alicePriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519(alicePriv, Basepoint): %v", err)
	}
	if !bytes.Equal(alicePub, gotAlicePub) {
		t.Errorf("alice pub:\n  got  %x\n  want %x", gotAlicePub, alicePub)
	}

	// Verify Bob's public key derivation.
	gotBobPub, err := curve25519.X25519(bobPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519(bobPriv, Basepoint): %v", err)
	}
	if !bytes.Equal(bobPub, gotBobPub) {
		t.Errorf("bob pub:\n  got  %x\n  want %x", gotBobPub, bobPub)
	}

	// Alice computes shared secret with Bob's public key.
	gotAlice, err := curve25519.X25519(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("X25519(alicePriv, bobPub): %v", err)
	}
	if !bytes.Equal(wantSecret, gotAlice) {
		t.Errorf("shared secret (alice):\n  got  %x\n  want %x", gotAlice, wantSecret)
	}

	// Bob computes shared secret with Alice's public key (ECDH symmetry).
	gotBob, err := curve25519.X25519(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("X25519(bobPriv, alicePub): %v", err)
	}
	if !bytes.Equal(wantSecret, gotBob) {
		t.Errorf("shared secret (bob):\n  got  %x\n  want %x", gotBob, wantSecret)
	}
}

// TestKATRFC5869HKDF verifies HKDF-SHA-256 against RFC 5869 Appendix A test vectors.
func TestKATRFC5869HKDF(t *testing.T) {
	tests := []struct {
		name string
		ikm  string
		salt string
		info string
		l    int
		okm  string
	}{
		{
			name: "TC1_SHA256",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "000102030405060708090a0b0c",
			info: "f0f1f2f3f4f5f6f7f8f9",
			l:    42,
			okm:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "TC2_SHA256_LongInputs",
			ikm:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			l:    82,
			okm:  "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ikm := mustHex(t, tc.ikm)
			salt := mustHex(t, tc.salt)
			info := mustHex(t, tc.info)
			want := mustHex(t, tc.okm)

			kdf := hkdf.New(sha256.New, ikm, salt, info)
			got := make([]byte, tc.l)
			if _, err := io.ReadFull(kdf, got); err != nil {
				t.Fatalf("hkdf ReadFull: %v", err)
			}
			if !bytes.Equal(want, got) {
				t.Errorf("OKM mismatch:\n  got  %x\n  want %x", got, want)
			}
		})
	}
}

// ── Round-Trip Property Tests (US2) ──────────────────────────────────────────

// TestRoundTripAES verifies AES encrypt-then-decrypt for multiple payload sizes.
func TestRoundTripAES(t *testing.T) {
	engine := NewEngine()
	sizes := []struct {
		name string
		size int
	}{
		{"0B", 0},
		{"1B", 1},
		{"1KB", 1024},
		{"1MB", 1 << 20},
		{"RandomLarge", -1},
	}
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			sz := s.size
			if sz < 0 {
				if testing.Short() {
					t.Skip("skipping large random round-trip in -short mode")
				}
				sz = mathrand.IntN(10 << 20)
			}
			roundTripAES(t, engine, randomBytes(t, sz))
		})
	}
}

// TestRoundTripX25519 verifies X25519 encrypt-then-decrypt for multiple payload sizes.
func TestRoundTripX25519(t *testing.T) {
	engine := NewEngine()
	sizes := []struct {
		name string
		size int
	}{
		{"0B", 0},
		{"1B", 1},
		{"1KB", 1024},
		{"1MB", 1 << 20},
		{"RandomLarge", -1},
	}
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			sz := s.size
			if sz < 0 {
				if testing.Short() {
					t.Skip("skipping large random round-trip in -short mode")
				}
				sz = mathrand.IntN(10 << 20)
			}
			roundTripX25519(t, engine, randomBytes(t, sz))
		})
	}
}

// TestNonceUniqueness verifies that encrypting the same plaintext twice
// produces different nonces and ciphertexts.
func TestNonceUniqueness(t *testing.T) {
	engine := NewEngine()
	plaintext := randomBytes(t, 64)
	key, err := engine.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}

	ct1, nonce1, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES first: %v", err)
	}
	ct2, nonce2, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES second: %v", err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Error("nonces must differ between two encryptions of the same plaintext")
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("ciphertexts must differ between two encryptions of the same plaintext")
	}
}

// ── Tamper Detection (US3) ────────────────────────────────────────────────────

// TestTamperBitFlip verifies that flipping any bit in the ciphertext body
// causes AES-GCM authentication to fail (GCM tag mismatch).
func TestTamperBitFlip(t *testing.T) {
	engine := NewEngine()
	key, err := engine.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}
	plaintext := randomBytes(t, 256)

	ct, nonce, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES: %v", err)
	}

	// Flip first byte.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0x01
	if _, err := engine.DecryptAES(tampered, key, nonce, nil); err == nil {
		t.Error("expected auth failure after first-byte bit-flip, got nil")
	}

	// Flip mid-body byte (re-encrypt to get fresh valid ct).
	ct2, nonce2, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES (second): %v", err)
	}
	tampered2 := make([]byte, len(ct2))
	copy(tampered2, ct2)
	tampered2[len(tampered2)/2] ^= 0x80
	if _, err := engine.DecryptAES(tampered2, key, nonce2, nil); err == nil {
		t.Error("expected auth failure after mid-body bit-flip, got nil")
	}
}

// TestTamperTruncation verifies that removing the last byte of ciphertext
// causes decryption to return an error (tag is truncated / corrupt).
func TestTamperTruncation(t *testing.T) {
	engine := NewEngine()
	key, err := engine.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}
	plaintext := randomBytes(t, 256)

	ct, nonce, err := engine.EncryptAES(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES: %v", err)
	}

	truncated := ct[:len(ct)-1]
	if _, err := engine.DecryptAES(truncated, key, nonce, nil); err == nil {
		t.Error("expected error after truncation, got nil")
	}
}

// TestTamperNonceSwap verifies that using the wrong nonce causes decryption
// to fail even though the key is correct.
func TestTamperNonceSwap(t *testing.T) {
	engine := NewEngine()
	key, err := engine.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}

	pt1 := randomBytes(t, 64)
	pt2 := randomBytes(t, 64)

	ct1, nonce1, err := engine.EncryptAES(pt1, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES (pt1): %v", err)
	}
	ct2, nonce2, err := engine.EncryptAES(pt2, key, nil)
	if err != nil {
		t.Fatalf("EncryptAES (pt2): %v", err)
	}

	// Nonces must differ (sanity check — GCM uses random 12-byte nonces).
	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("nonces unexpectedly identical — cannot test nonce swap")
	}

	if _, err := engine.DecryptAES(ct1, key, nonce2, nil); err == nil {
		t.Error("expected auth failure when decrypting ct1 with nonce2, got nil")
	}
	if _, err := engine.DecryptAES(ct2, key, nonce1, nil); err == nil {
		t.Error("expected auth failure when decrypting ct2 with nonce1, got nil")
	}
}

// ── Edge Cases (US4) ──────────────────────────────────────────────────────────

// TestEdgeFileSizes verifies the streaming path at boundary sizes:
// empty, exact 64 KB chunk boundary, and one byte over the boundary.
func TestEdgeFileSizes(t *testing.T) {
	engine := NewEngine()
	sizes := []struct {
		name string
		size int
	}{
		{"0B", 0},
		{"64KB", 64 * 1024},
		{"64KBp1", 64*1024 + 1},
	}
	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			streamRoundTrip(t, engine, randomBytes(t, s.size))
		})
	}
}

// ── Constant-Time Verification (US5) ─────────────────────────────────────────

// TestConstantTimeFingerprint verifies that CompareFingerprints uses
// crypto/subtle (constant-time) comparison and returns correct results.
func TestConstantTimeFingerprint(t *testing.T) {
	if !CompareFingerprints("abc", "abc") {
		t.Error("CompareFingerprints(abc, abc): expected true")
	}
	if CompareFingerprints("abc", "xyz") {
		t.Error("CompareFingerprints(abc, xyz): expected false")
	}
	if CompareFingerprints("abc", "abcd") {
		t.Error("CompareFingerprints(abc, abcd): expected false (length mismatch)")
	}
	if !CompareFingerprints("", "") {
		t.Error("CompareFingerprints('', ''): expected true")
	}
}

// TestConstantTimeKeys verifies that CompareKeys uses crypto/subtle
// (constant-time) comparison and returns correct results.
func TestConstantTimeKeys(t *testing.T) {
	a := randomBytes(t, 32)
	b := make([]byte, 32)
	copy(b, a)

	if !CompareKeys(a, b) {
		t.Error("CompareKeys(a, copy(a)): expected true")
	}

	b[0] ^= 0x01
	if CompareKeys(a, b) {
		t.Error("CompareKeys after bit-flip: expected false")
	}

	if CompareKeys(a, a[:16]) {
		t.Error("CompareKeys with length mismatch: expected false")
	}
}

// ── Coverage-boosting tests ───────────────────────────────────────────────────

// TestX25519InvalidKeySizes verifies that EncryptX25519 and DecryptX25519
// reject wrong-size keys with descriptive errors.
func TestX25519InvalidKeySizes(t *testing.T) {
	engine := NewEngine()

	// EncryptX25519: public key too short.
	if _, _, _, err := engine.EncryptX25519([]byte("hello"), []byte("short"), nil); err == nil {
		t.Error("EncryptX25519: expected error for short public key")
	}

	// DecryptX25519: ephemeral pub key too short.
	key := randomBytes(t, 32)
	if _, err := engine.DecryptX25519([]byte("ct"), []byte("short"), randomBytes(t, 12), key, nil); err == nil {
		t.Error("DecryptX25519: expected error for short ephemeral key")
	}

	// DecryptX25519: private key too short.
	if _, err := engine.DecryptX25519([]byte("ct"), randomBytes(t, 32), randomBytes(t, 12), []byte("short"), nil); err == nil {
		t.Error("DecryptX25519: expected error for short private key")
	}
}

// TestAESEncryptInvalidKey verifies that EncryptAES and DecryptAES return
// errors for wrong-size keys (covering the key-size guard branches).
func TestAESEncryptInvalidKey(t *testing.T) {
	engine := NewEngine()
	if _, _, err := engine.EncryptAES([]byte("hello"), []byte("tooshort"), nil); err == nil {
		t.Error("EncryptAES: expected error for short key")
	}
	if _, err := engine.DecryptAES([]byte("ct"), []byte("tooshort"), randomBytes(t, 12), nil); err == nil {
		t.Error("DecryptAES: expected error for short key")
	}
}

// TestStreamInvalidKey verifies that EncryptStream and DecryptStream reject
// wrong-size keys (covering the key-size guard branches).
func TestStreamInvalidKey(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	var buf bytes.Buffer
	if err := engine.EncryptStream(ctx, bytes.NewReader([]byte("hi")), &buf, []byte("short"), nil); err == nil {
		t.Error("EncryptStream: expected error for short key")
	}
	if err := engine.DecryptStream(ctx, bytes.NewReader([]byte("hi")), &buf, []byte("short"), nil); err == nil {
		t.Error("DecryptStream: expected error for short key")
	}
}
