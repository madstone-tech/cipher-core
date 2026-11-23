package cipher_test

import (
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// externalLogger is defined entirely outside the cipher package and imports no
// internal path. It compiles against Config.Logger only if that field's type is
// declared by pkg/cipher itself.
type externalLogger struct{ infos int }

func (l *externalLogger) Debug(string, map[string]interface{}) {}
func (l *externalLogger) Info(string, map[string]interface{})  { l.infos++ }
func (l *externalLogger) Warn(string, map[string]interface{})  {}
func (l *externalLogger) Error(string, map[string]interface{}) {}

// externalProgress likewise pins ProgressReporter to a public type.
type externalProgress struct{ calls int }

func (p *externalProgress) ReportProgress(string, int) { p.calls++ }
func (p *externalProgress) ReportError(error)          {}
func (p *externalProgress) ReportSuccess(string)       {}

func TestConfigAcceptsCallerSuppliedPorts(t *testing.T) {
	lg := &externalLogger{}
	pr := &externalProgress{}

	client, err := cipher.New(cipher.Config{
		DBPath:   filepath.Join(t.TempDir(), "ports.db"),
		Logger:   lg,
		Progress: pr,
	})
	if err != nil {
		t.Fatalf("New with caller-supplied ports: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
}
