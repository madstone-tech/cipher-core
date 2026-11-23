package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
)

// stdinPath is the --*-file value that reads the secret from standard input.
const stdinPath = "-"

// maxSecretFileSize bounds a secret read from a file or stdin.
const maxSecretFileSize = 64 << 10

// secretFromFile reads a secret from path, or from stdin when path is "-".
// One trailing "\n" or "\r\n" is removed; everything else is kept as is.
// An empty result is an error.
func secretFromFile(path string) (string, error) {
	var (
		data []byte
		err  error
	)
	if path == stdinPath {
		data, err = readBounded(os.Stdin)
	} else {
		data, err = readFileBounded(path)
	}
	if err != nil {
		return "", err
	}

	s := string(data)
	if t, ok := strings.CutSuffix(s, "\r\n"); ok {
		s = t
	} else if t, ok := strings.CutSuffix(s, "\n"); ok {
		s = t
	}
	if s == "" {
		if path == stdinPath {
			return "", errors.New("secret from stdin is empty")
		}
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return s, nil
}

func readFileBounded(path string) (data []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close secret file: %w", cerr))
		}
	}()
	return readBounded(f)
}

func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSecretFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	if len(data) > maxSecretFileSize {
		return nil, fmt.Errorf("secret is larger than %d bytes", maxSecretFileSize)
	}
	return data, nil
}

// cliPrompter is the prompter the CLI gives to the usecases.
//
// A passphrase prompt returns keyPassphrase when it is set (from
// --key-passphrase-file). Without a terminal on stdin, a passphrase prompt
// fails with an error that names the flag for the secret, instead of printing
// the prompt and failing on the terminal read.
type cliPrompter struct {
	*cli.Prompter
	ctx           context.Context
	interactive   bool
	keyPassphrase string
}

// newCLIPrompter returns a cliPrompter for this process. keyPassphrase may be
// "". ctx is the command context: SIGINT or SIGTERM ends a passphrase prompt.
func newCLIPrompter(ctx context.Context, keyPassphrase string) *cliPrompter {
	return &cliPrompter{
		Prompter:      cli.NewPrompter(),
		ctx:           ctx,
		interactive:   term.IsTerminal(int(os.Stdin.Fd())),
		keyPassphrase: keyPassphrase,
	}
}

// PromptPassphrase implements usecases.UserPrompter.
func (p *cliPrompter) PromptPassphrase(prompt string) (string, error) {
	isFilePassword := strings.Contains(prompt, "file password")
	if p.keyPassphrase != "" && !isFilePassword {
		return p.keyPassphrase, nil
	}
	if !p.interactive {
		flag := "--key-passphrase-file"
		if isFilePassword {
			flag = "--password-file"
		}
		return "", fmt.Errorf("no terminal to ask %q: supply the secret with %s", strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(prompt), ":")), flag)
	}
	return p.readPassphrase(prompt)
}

// readPassphrase reads a hidden line from the terminal, and returns early
// with the context error when the command is cancelled (Ctrl-C): the command
// catches SIGINT, so a plain terminal read would ignore it (T-6). The terminal
// mode is restored on that path, so echo comes back on.
func (p *cliPrompter) readPassphrase(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return "", fmt.Errorf("read terminal state: %w", err)
	}
	type result struct {
		s   string
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := p.Prompter.PromptPassphrase(prompt)
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		return r.s, r.err
	case <-p.ctx.Done():
		if err := term.Restore(fd, state); err != nil {
			return "", errors.Join(p.ctx.Err(), fmt.Errorf("restore terminal: %w", err))
		}
		fmt.Println()
		return "", p.ctx.Err()
	}
}
