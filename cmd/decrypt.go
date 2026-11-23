package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// decryptResult is the JSON output structure for the decrypt command.
type decryptResult struct {
	OutputPath string `json:"output_path"`
	Method     string `json:"method"`
	Version    uint8  `json:"version"`
	// OriginalFilename is the sender's informational name from the header.
	// It was not used for the output path.
	OriginalFilename string `json:"original_filename,omitempty"`
}

type DecryptCommand struct {
	dbPath     string
	jsonOutput bool
	verbose    bool
}

func NewDecryptCommand(dbPath string, jsonOutput bool, verbose bool) *DecryptCommand {
	return &DecryptCommand{
		dbPath:     dbPath,
		jsonOutput: jsonOutput,
		verbose:    verbose,
	}
}

// Execute decrypts filePath. password is the file password (method 3);
// keyPassphrase unlocks the local private key. Either may be "": the command
// then prompts on a terminal, or fails and names the flag without one.
func (c *DecryptCommand) Execute(ctx context.Context, filePath, password, keyPassphrase, outputPath string, overwrite bool) (err error) {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close database: %w", cerr)
		}
	}()

	fileHandler := cli.NewFileHandler()
	progress := cli.NewCommandProgress(c.jsonOutput)
	prompter := newCLIPrompter(ctx, "")

	decryptUC := usecases.NewDecryptFile(
		adapters.KeyRepo,
		adapters.CryptoEngine,
		adapters.KEKProvider,
		adapters.SessionStore,
		adapters.Encoder,
		fileHandler,
		progress,
		prompter,
		adapters.Logger,
	).ProtectKeyStore(protectedKeyStores(c.dbPath)...)

	resp, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:           filePath,
		Passphrase:         password,
		RecoveryPassphrase: keyPassphrase,
		OutputPath:         outputPath,
		Overwrite:          overwrite,
	})
	if err != nil {
		return withOutputHint(err)
	}

	if c.jsonOutput {
		out, err := json.Marshal(decryptResult{OutputPath: resp.OutputPath, Method: string(resp.Method), Version: resp.Version, OriginalFilename: resp.OriginalFilename})
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("\nDecrypted file: %s\n", resp.OutputPath)
		if resp.OriginalFilename != "" {
			// Quoted: the sender chose this name. It was not used as a path.
			fmt.Printf("Sender's file name: %q\n", resp.OriginalFilename)
		}
		fmt.Printf("Method: %s\n", resp.Method)
	}

	return nil
}
