package cipher

import "github.com/madstone-tech/cipher-core/internal/core/usecases"

// Logger receives structured log output from a Client. Implement it to route
// the SDK's logs into your own logging stack.
//
// The internal port this adapts also carries a WithFields method. It is
// deliberately omitted here: callers gain nothing from it, and including it
// would make the interface self-referential across the package boundary.
type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
}

// ProgressReporter receives progress callbacks from long-running operations
// such as streaming encryption.
type ProgressReporter interface {
	ReportProgress(message string, percent int)
	ReportError(err error)
	ReportSuccess(message string)
}

// loggerAdapter lets a caller-supplied Logger satisfy the internal port.
// WithFields returns the adapter unchanged: the public interface has no
// field-scoping concept, so scoped fields are dropped rather than silently
// misattributed to a logger that never agreed to carry them.
type loggerAdapter struct{ inner Logger }

func (a loggerAdapter) Debug(msg string, fields map[string]interface{}) { a.inner.Debug(msg, fields) }

func (a loggerAdapter) Info(msg string, fields map[string]interface{}) { a.inner.Info(msg, fields) }

func (a loggerAdapter) Warn(msg string, fields map[string]interface{}) { a.inner.Warn(msg, fields) }

func (a loggerAdapter) Error(msg string, fields map[string]interface{}) { a.inner.Error(msg, fields) }

func (a loggerAdapter) WithFields(map[string]interface{}) usecases.Logger { return a }

// progressAdapter lets a caller-supplied ProgressReporter satisfy the
// internal port. The two are structurally identical, so this is a pure
// type bridge.
type progressAdapter struct{ inner ProgressReporter }

func (a progressAdapter) ReportProgress(msg string, percent int) {
	a.inner.ReportProgress(msg, percent)
}
func (a progressAdapter) ReportError(err error)    { a.inner.ReportError(err) }
func (a progressAdapter) ReportSuccess(msg string) { a.inner.ReportSuccess(msg) }
