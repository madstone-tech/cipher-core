package crypto

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Header JSON limits (docs/format-spec.md §Header JSON, "JSON rules"). Two
// conforming readers must agree on whether a header parses, so the rules are
// stricter than RFC 8259 and the same in Go and in the spec Python.
const (
	// maxHeaderDepth is the deepest nesting of objects and arrays. The
	// header uses 3 (object → recipients array → block object).
	maxHeaderDepth = 8
	// maxHeaderInteger is 2^53 − 1: every reader can hold it exactly.
	maxHeaderInteger = 1<<53 - 1
)

// checkHeaderJSON applies the JSON rules that the decoding library does not:
//   - every number is a non-negative integer, written without sign, fraction,
//     or exponent, and at most 2^53 − 1;
//   - objects and arrays nest at most maxHeaderDepth levels.
//
// The tokenizer itself rejects invalid UTF-8, lone surrogate escapes, NaN and
// Infinity, and duplicate member names.
func checkHeaderJSON(data []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid header JSON: %w", err)
		}
		switch tok.Kind() {
		case '{', '[':
			if dec.StackDepth() > maxHeaderDepth {
				return fmt.Errorf("header JSON nests deeper than %d levels", maxHeaderDepth)
			}
		case '0':
			if err := checkHeaderNumber(tok.String()); err != nil {
				return err
			}
		}
	}
}

func checkHeaderNumber(lit string) error {
	for _, c := range lit {
		if c < '0' || c > '9' {
			return fmt.Errorf("header JSON number %q is not a non-negative integer", lit)
		}
	}
	if len(lit) > 1 && lit[0] == '0' {
		return fmt.Errorf("header JSON number %q has a leading zero", lit)
	}
	n, err := strconv.ParseUint(lit, 10, 64)
	if err != nil || n > maxHeaderInteger {
		return fmt.Errorf("header JSON number %q is larger than 2^53 - 1", lit)
	}
	return nil
}
