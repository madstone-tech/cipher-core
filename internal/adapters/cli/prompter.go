package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompter implements the UserPrompter interface
type Prompter struct {
	reader *bufio.Reader
}

// NewPrompter creates a new prompter
func NewPrompter() *Prompter {
	return &Prompter{
		reader: bufio.NewReader(os.Stdin),
	}
}

// PromptString prompts for a string input
func (p *Prompter) PromptString(prompt string) (string, error) {
	fmt.Print(prompt)
	input, err := p.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// PromptConfirm prompts for yes/no confirmation
func (p *Prompter) PromptConfirm(prompt string) (bool, error) {
	fmt.Printf("%s (y/n): ", prompt)
	input, err := p.reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	input = strings.ToLower(strings.TrimSpace(input))
	return input == "y" || input == "yes", nil
}

// PromptPassphrase prompts for a passphrase (hidden input)
func (p *Prompter) PromptPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // New line after hidden input
	if err != nil {
		return "", err
	}
	return string(passBytes), nil
}
