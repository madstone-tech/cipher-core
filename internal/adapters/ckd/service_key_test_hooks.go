package ckd

// Test-only indirection over the pinned service key. Production code always
// uses the constants; tests swap the pinned key to sign responses without
// holding the real private half (which lives server-side). The hooks live in
// a non-test file so the *_test.go (external ckd_test package) can reach
// them via exported functions below.

var (
	testServiceKey  []byte // active ed25519 public key when overridden
	testServiceID   string // active key id when overridden
	testHookEnabled bool
)

// pinnedVerificationKey returns the active public key for verification.
func pinnedVerificationKey() ([]byte, error) {
	if testHookEnabled {
		return testServiceKey, nil
	}
	return pinnedKDServiceKey()
}

// pinnedVerificationID returns the active key id for verification.
func pinnedVerificationID() string {
	if testHookEnabled {
		return testServiceID
	}
	return KDServiceKeyID
}

// TestOverrideServiceKey installs a test verification key + key id.
func TestOverrideServiceKey(t interface{ Helper() }, pub []byte, keyID string) {
	t.Helper()
	testServiceKey = pub
	testServiceID = keyID
	testHookEnabled = true
}

// TestResetServiceKey restores the pinned production key.
func TestResetServiceKey(t interface{ Helper() }) {
	t.Helper()
	testServiceKey = nil
	testServiceID = ""
	testHookEnabled = false
}

// TestSetMadstoneBaseURL points the client's hosted-directory lookups at a
// test server (used by tests that need real LookupKey routing).
func (c *Client) TestSetMadstoneBaseURL(url string) {
	c.madstoneBaseURL = url
}

// HashEmailForTest exposes hashEmail for fixture covered-content builders.
func HashEmailForTest(email string) string { return hashEmail(email) }

// CoveredContentForTest exposes the covered-content builder.
func CoveredContentForTest(emailHash string, body []byte) []byte {
	return kdCoveredContent(emailHash, body)
}
