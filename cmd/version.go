package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// Build variables injected via ldflags by GoReleaser.
var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
	builtBy   = "unknown"
)

// VersionCommand displays version information.
type VersionCommand struct{}

// Execute prints version info. If jsonOutput is true, output is JSON.
func (c *VersionCommand) Execute(jsonOutput bool) error {
	if jsonOutput {
		info := map[string]string{
			"version":   version,
			"commit":    commit,
			"buildTime": buildTime,
			"builtBy":   builtBy,
			"goVersion": runtime.Version(),
			"os":        runtime.GOOS,
			"arch":      runtime.GOARCH,
		}
		if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
			return fmt.Errorf("failed to write version JSON: %w", err)
		}
		return nil
	}

	fmt.Printf("mdstn-cipher %s (commit %s, built %s by %s, %s, %s/%s)\n",
		version, commit, buildTime, builtBy, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// Version reports the build version for consumers (a consuming server passes
// it to telemetry + /health). ldflags-injected at build: the binary's
// main package copies it through.
func Version() string { return version }
