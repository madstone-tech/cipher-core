// The mdstn-cipher entrypoint. The command surface lives in the cmd package
// (package cmd); this wrapper is the package-main the go tool can link.
package main

import (
	"fmt"
	"os"

	"github.com/madstone-tech/cipher-core/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cmd.ExitCode(err))
	}
}
