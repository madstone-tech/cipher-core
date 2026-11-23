package crypto

import "testing"

// FuzzDecode fuzzes the .mdstn binary format decoder.
// It must never panic — malformed input may only return errors.
func FuzzDecode(f *testing.F) {
	// Seed corpus: various v1 headers, edge cases, a retired version-2 header,
	// and format v2 (version 0x03) headers.
	f.Add([]byte("MDST"))
	f.Add([]byte("MDST\x01\x01\x00\x00"))
	f.Add([]byte{})
	f.Add([]byte("MDST\x01\x01\x00\x02{}"))

	// Retired pre-release header: MDST + version=2 + method=1 + headerLen(2B) + headerJSON.
	v2JSON := []byte(`{"method":"aes256-gcm","key_id":"k","recipient_key_id":"","ephemeral_pub_key":null,"salt":null,"nonce":null,"original_filename":"f","encrypted_at":0}`)
	v2Seed := make([]byte, 0, 8+len(v2JSON))
	v2Seed = append(v2Seed, []byte("MDST")...)
	v2Seed = append(v2Seed, 0x02)                                    // version 2
	v2Seed = append(v2Seed, 0x01)                                    // method AES256
	v2Seed = append(v2Seed, byte(len(v2JSON)>>8), byte(len(v2JSON))) // big-endian header length
	v2Seed = append(v2Seed, v2JSON...)
	f.Add(v2Seed)

	// Format v2 (0x03) method-2 and method-3 headers.
	for _, seed := range []struct {
		method byte
		json   string
	}{
		{2, `{"chunked":false,"encrypted_at":0,"original_filename":"f","recipients":[{"ephemeral_pub_key":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=","nonce":"QkJCQkJCQkJCQkJC","wrapped_cek":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"}]}`},
		{3, `{"chunked":true,"encrypted_at":0,"kdf":"argon2id","m":65536,"original_filename":"f","p":4,"salt":"QkJCQkJCQkJCQkJCQkJCQg==","t":3}`},
	} {
		b := append([]byte("MDST"), 0x03, seed.method, byte(len(seed.json)>>8), byte(len(seed.json)))
		f.Add(append(b, seed.json...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fe := NewFileEncoder()
		_, _ = fe.Decode(data) // must not panic
	})
}
