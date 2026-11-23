package cli

import (
	"fmt"
	"io"
	"os"
)

// Progress implements the ProgressReporter interface. Progress and success
// lines go to out; errors go to stderr.
type Progress struct {
	out io.Writer
}

// NewProgress returns a progress reporter that writes progress and success
// lines to out.
func NewProgress(out io.Writer) *Progress {
	return &Progress{out: out}
}

// NewCommandProgress returns the progress reporter of a CLI command: stdout
// for human output, stderr in --json mode, where stdout holds only the JSON
// value.
func NewCommandProgress(jsonOutput bool) *Progress {
	if jsonOutput {
		return NewProgress(os.Stderr)
	}
	return NewProgress(os.Stdout)
}

// ReportProgress reports progress to out.
func (p *Progress) ReportProgress(message string, percent int) {
	fmt.Fprintf(p.out, "[%3d%%] %s\n", percent, message) //nolint:errcheck // best-effort: a progress line has no caller to report a write error to
}

// ReportError reports an error to stderr.
func (p *Progress) ReportError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
}

// ReportSuccess reports success to out.
func (p *Progress) ReportSuccess(message string) {
	fmt.Fprintf(p.out, "✓ %s\n", message) //nolint:errcheck // best-effort: a progress line has no caller to report a write error to
}
