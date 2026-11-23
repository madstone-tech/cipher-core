package usecases

import (
	"cmp"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// maxSingleFrameBody bounds the single-frame body after the header MAC: a
// single-frame plaintext is shorter than streamingThreshold (1 MiB), so the
// rest of the body is at most nonce(12) + (1 MiB − 1) + tag(16).
const maxSingleFrameBody = 12 + streamingThreshold - 1 + 16

// DecryptFileRequest contains parameters for file decryption
type DecryptFileRequest struct {
	FilePath           string
	Passphrase         string // Optional, for passphrase-encrypted files
	RecoveryPassphrase string // Optional, for KEK unwrapping (Argon2id) — used by MCP headless mode
	// OutputPath is optional. An explicit path replaces an existing file.
	// When it is empty, the output goes next to the input file (see
	// defaultOutputPath) and never replaces an existing file unless Overwrite.
	OutputPath string
	Overwrite  bool
}

// DecryptStreamRequest contains the parameters of DecryptFile.DecryptStream.
type DecryptStreamRequest struct {
	Passphrase         string // file password (method 3); prompted if empty
	RecoveryPassphrase string // key passphrase or 24-word recovery phrase (method 2)
}

// DecryptFileResponse contains the result of decryption
type DecryptFileResponse struct {
	OutputPath       string // empty for DecryptStream
	Method           entities.EncryptionMethod
	OriginalFilename string
	Version          uint8 // container version byte (always 0x03 today)
}

// DecryptFile decrypts a .mdstn file
type DecryptFile struct {
	keyRepo      KeyRepository
	crypto       CryptoEngine
	kekProvider  KEKProvider
	sessionStore SessionStore
	encoder      FileEncoder
	fileHandler  FileHandler
	progress     ProgressReporter
	prompter     UserPrompter
	logger       Logger
	keyStores    []string // key database DSNs whose files no output may replace
}

// NewDecryptFile creates a new DecryptFile usecase
func NewDecryptFile(
	keyRepo KeyRepository,
	crypto CryptoEngine,
	kekProvider KEKProvider,
	sessionStore SessionStore,
	encoder FileEncoder,
	fileHandler FileHandler,
	progress ProgressReporter,
	prompter UserPrompter,
	logger Logger,
) *DecryptFile {
	return &DecryptFile{
		keyRepo:      keyRepo,
		crypto:       crypto,
		kekProvider:  kekProvider,
		sessionStore: sessionStore,
		encoder:      encoder,
		fileHandler:  fileHandler,
		progress:     progress,
		prompter:     prompter,
		logger:       logger,
	}
}

// Execute decrypts req.FilePath. It reads the header from a stream, then
// decrypts the body into a StagedWriter: nothing appears at the output path
// unless the whole body authenticates.
func (uc *DecryptFile) Execute(ctx context.Context, req *DecryptFileRequest) (*DecryptFileResponse, error) {
	if req.FilePath == "" {
		return nil, entities.ErrInvalidInput
	}

	uc.progress.ReportProgress("Reading encrypted file...", 10)
	reader, err := uc.fileHandler.ReadStream(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer reader.Close() //nolint:errcheck // best-effort: read-only close

	uc.progress.ReportProgress("Parsing file format...", 20)
	encFile, headerAAD, err := uc.encoder.DecodeHeader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file: %w", err)
	}

	outputPath, exclusive := req.OutputPath, false
	if outputPath == "" {
		outputPath, exclusive = defaultOutputPath(req.FilePath), !req.Overwrite
	}
	// Never write the plaintext over its own ciphertext (not with an explicit
	// path, and not with Overwrite), and never into a directory path (S-7).
	if err := CheckOutputPath(uc.fileHandler, req.FilePath, outputPath, uc.keyStores); err != nil {
		return nil, err
	}
	// Fail before any prompt or KDF when the default path is taken (T-7).
	if exclusive {
		if err := refuseExisting(uc.fileHandler, outputPath); err != nil {
			return nil, err
		}
	}

	// Shared-key files exist to let a managing client (e.g. a browser-based app)
	// decrypt key material; the CLI has no access to the server-side policy.
	if encFile.Method == entities.MethodSharedKey {
		return nil, fmt.Errorf("shared-key files can only be decrypted by the managing client")
	}

	writer, err := openOutput(uc.fileHandler, outputPath, exclusive)
	if err != nil {
		return nil, err
	}
	sreq := &DecryptStreamRequest{Passphrase: req.Passphrase, RecoveryPassphrase: req.RecoveryPassphrase}
	use, err := uc.decryptBody(ctx, reader, writer, encFile, headerAAD, sreq)
	if err != nil {
		use.discard(uc)
		return nil, errors.Join(err, writer.Abort())
	}
	if err := commitOutput(ctx, writer); err != nil {
		use.discard(uc)
		return nil, err
	}
	// Only now does the file count as used: it authenticated and its output
	// is published (R-7, R-8).
	use.apply(ctx, uc)

	uc.progress.ReportSuccess("File decrypted successfully")
	return &DecryptFileResponse{OutputPath: outputPath, Method: encFile.Method, OriginalFilename: encFile.OriginalFilename, Version: encFile.Version}, nil
}

// defaultOutputPath returns the output path when the caller gave none: the
// input path without ".mdstn", or the input path plus ".decrypted". It never
// uses the header's original_filename: the sender chooses that value, and a
// sender-chosen name can still be harmful in the input's directory (a
// dotfile such as ".zshenv", a device name, or the name of another file).
func defaultOutputPath(inputPath string) string {
	name := strings.TrimSuffix(inputPath, ".mdstn")
	if base := filepath.Base(name); name != inputPath && base != "." && base != ".." &&
		!strings.HasSuffix(name, string(filepath.Separator)) && !strings.HasSuffix(name, "/") {
		return name
	}
	return inputPath + ".decrypted"
}

// DecryptStream reads one container from src and writes its plaintext to dst.
// A stream body is authenticated chunk by chunk before each chunk is written;
// if DecryptStream returns an error, dst can hold plaintext of earlier chunks
// and the caller MUST discard it. Nothing is written, and nothing after the
// header MAC is read, unless the header MAC verifies. Errors match
// ErrHeaderAuthFailed, ErrNotARecipient, or ErrWrongPassword with errors.Is.
func (uc *DecryptFile) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, req *DecryptStreamRequest) (*DecryptFileResponse, error) {
	encFile, headerAAD, err := uc.encoder.DecodeHeader(src)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file: %w", err)
	}
	if encFile.Method == entities.MethodSharedKey {
		return nil, fmt.Errorf("shared-key files can only be decrypted by the managing client")
	}
	use, err := uc.decryptBody(ctx, src, dst, encFile, headerAAD, req)
	if err != nil {
		use.discard(uc)
		return nil, err
	}
	use.apply(ctx, uc)
	return &DecryptFileResponse{Method: encFile.Method, OriginalFilename: encFile.OriginalFilename, Version: encFile.Version}, nil
}

// decryptBody reads the header MAC, resolves the file key, verifies the MAC,
// and only then decrypts the body that follows in src (docs/format-spec.md
// §Error classes):
//   - method 2: a recipient block that unwraps but whose CEK fails the MAC is
//     tampering (ErrHeaderAuthFailed), not "not a recipient";
//   - method 3: a MAC failure is ErrWrongPassword;
//   - after the MAC verifies, every body failure is ErrHeaderAuthFailed.
func (uc *DecryptFile) decryptBody(ctx context.Context, src io.Reader, dst io.Writer, encFile *entities.EncryptedFile, headerAAD []byte, req *DecryptStreamRequest) (*keyUse, error) {
	if encFile.Method != entities.MethodX25519 && encFile.Method != entities.MethodPassphrase {
		return nil, fmt.Errorf("unsupported encryption method: %s", encFile.Method)
	}

	headerMAC := make([]byte, entities.HeaderMACSize)
	if _, err := io.ReadFull(src, headerMAC); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	fileKey, use, err := uc.resolveFileKey(ctx, encFile, req)
	if err != nil {
		return nil, err
	}
	defer clear(fileKey)

	ok, err := uc.crypto.VerifyHeaderMAC(fileKey, headerAAD, headerMAC)
	if err != nil {
		return use, fmt.Errorf("failed to verify header MAC: %w", err)
	}
	if !ok {
		if encFile.Method == entities.MethodPassphrase {
			return use, entities.ErrWrongPassword
		}
		return use, fmt.Errorf("%w: a recipient block opened, but the header MAC does not verify with its key", entities.ErrHeaderAuthFailed)
	}
	payloadKey, err := uc.crypto.DerivePayloadKey(fileKey)
	if err != nil {
		return use, fmt.Errorf("failed to derive payload key: %w", err)
	}
	defer clear(payloadKey)

	if encFile.Chunked {
		uc.progress.ReportProgress("Decrypting (streaming)...", 40)
		if err := uc.crypto.DecryptStream(ctx, src, dst, payloadKey, headerAAD); err != nil {
			return use, fmt.Errorf("streaming decryption failed: %w", err)
		}
		return use, nil
	}

	// Single frame (chunked=false): [body_nonce(12)][ciphertext+tag].
	body, err := readSingleFrameBody(src)
	if err != nil {
		return use, err
	}
	uc.progress.ReportProgress("Decrypting...", 40)
	plaintext, err := uc.crypto.DecryptAES(body[12:], payloadKey, body[:12], headerAAD)
	if err != nil {
		return use, fmt.Errorf("%w: body decryption failed", entities.ErrHeaderAuthFailed)
	}
	defer clear(plaintext)

	uc.progress.ReportProgress("Writing decrypted file...", 80)
	if _, err := dst.Write(plaintext); err != nil {
		return use, fmt.Errorf("failed to write file: %w", err)
	}
	return use, nil
}

// readSingleFrameBody reads the rest of src (after the header MAC) as a
// single-frame body: nonce(12) || ciphertext+tag, at most maxSingleFrameBody
// bytes. The header MAC has verified, so a wrong length is tampering.
func readSingleFrameBody(src io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(src, maxSingleFrameBody+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	if len(body) > maxSingleFrameBody {
		return nil, fmt.Errorf("%w: single-frame body exceeds %d bytes: files of 1 MiB or more use the stream framing", entities.ErrHeaderAuthFailed, maxSingleFrameBody)
	}
	if len(body) < 12+16 {
		return nil, fmt.Errorf("%w: body too short: expected nonce(12)+ciphertext+tag, got %d bytes", entities.ErrHeaderAuthFailed, len(body))
	}
	return body, nil
}

// resolveFileKey returns the file key: the Argon2id key of the file password
// (method 3) or the CEK of the first recipient block that a local key opens
// (method 2).
//
// For method 2 it also returns the pending keyUse of the local key that opened
// a block. The caller applies it (usage counter, session cache) only after the
// file authenticates and its output is published, and discards it otherwise:
// a tampered file cannot change the usage counters or add a cache entry.
// (Keys that were already unlocked stay cached, and are tried first.)
func (uc *DecryptFile) resolveFileKey(ctx context.Context, encFile *entities.EncryptedFile, req *DecryptStreamRequest) ([]byte, *keyUse, error) {
	switch encFile.Method {
	case entities.MethodPassphrase:
		key, err := uc.derivePassphraseKey(encFile, req.Passphrase)
		return key, nil, err
	case entities.MethodX25519:
		return uc.findRecipientKey(ctx, encFile, req.RecoveryPassphrase)
	default:
		return nil, nil, fmt.Errorf("unsupported encryption method: %s", encFile.Method)
	}
}

// derivePassphraseKey prompts for the file password if needed and derives the
// file key with Argon2id. The header was already checked for the fixed
// Argon2id parameters when it was parsed.
func (uc *DecryptFile) derivePassphraseKey(encFile *entities.EncryptedFile, passphrase string) ([]byte, error) {
	if passphrase == "" {
		var err error
		passphrase, err = uc.prompter.PromptPassphrase("Enter file password: ")
		if err != nil {
			return nil, fmt.Errorf("failed to read file password: %w", err)
		}
	}
	key, err := uc.crypto.DeriveFileKeyArgon2id(passphrase, encFile.Salt)
	if err != nil {
		return nil, entities.ErrDecryptionFailed
	}
	return key, nil
}

// resolvePrivateKey unwraps the private key for the given identity key and
// returns it, a cleanup function that zeroes it, and the KEK when it was
// derived from a passphrase in this call (nil from the cache or a phrase).
//
// A supplied passphrase (or recovery phrase) is ALWAYS checked: a cached KEK is
// used only when the caller supplied no passphrase. Otherwise a caller with a
// wrong passphrase could decrypt with a KEK that another caller unlocked (N1).
func (uc *DecryptFile) resolvePrivateKey(ctx context.Context, key *entities.IdentityKey, passphrase string) ([]byte, func(), []byte, error) {
	noop := func() {}

	// Recovery-phrase path: re-derive the private key without the KEK/session
	// cache. The phrase must belong to this key.
	if priv, pub, ok, err := uc.mnemonicKey(passphrase); err != nil {
		return nil, noop, nil, err
	} else if ok {
		if subtle.ConstantTimeCompare(pub, key.PublicKey) != 1 {
			clear(priv)
			return nil, noop, nil, fmt.Errorf("the recovery phrase does not belong to key %s", key.ID)
		}
		return priv, func() { clear(priv) }, nil, nil
	}

	// Every key MUST be Argon2id-wrapped; raw/legacy private keys are no longer
	// supported (a zero-knowledge server never stores an unwrapped private key).
	if len(key.Argon2idSalt) == 0 {
		return nil, noop, nil, fmt.Errorf("key %s has no Argon2id salt and cannot be unwrapped", key.ID)
	}

	// Only an empty passphrase may use the session cache. A wrong supplied
	// passphrase fails and leaves the cache alone: the cached KEK belongs to
	// the caller who unlocked the key.
	if passphrase == "" {
		kek, err := uc.sessionStore.GetKEK(key.ID)
		if err != nil {
			return nil, noop, nil, fmt.Errorf("session store error: %w", err)
		}
		if kek != nil {
			privateKey, err := uc.kekProvider.UnwrapKey(key.WrappedPrivateKey, kek, key.ID)
			uc.kekProvider.ZeroKEK(kek)
			if err == nil {
				return privateKey, func() { uc.kekProvider.ZeroKEK(privateKey) }, nil, nil
			}
			// A stale cached KEK: drop it and ask for the passphrase.
			if cerr := uc.sessionStore.ClearKey(key.ID); cerr != nil {
				uc.logger.Warn("Failed to clear cached KEK", map[string]interface{}{"key_id": key.ID, "error": cerr.Error()})
			}
		}
		passphrase, err = uc.prompter.PromptPassphrase(keyPassphrasePrompt(key))
		if err != nil {
			return nil, noop, nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		if passphrase == "" {
			return nil, noop, nil, fmt.Errorf("passphrase is required to unlock key %s", key.ID)
		}
	}

	kek, err := uc.kekProvider.DeriveKEK(passphrase, key.Argon2idSalt)
	if err != nil {
		return nil, noop, nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	privateKey, err := uc.kekProvider.UnwrapKey(key.WrappedPrivateKey, kek, key.ID)
	if err != nil {
		uc.kekProvider.ZeroKEK(kek)
		return nil, noop, nil, fmt.Errorf("failed to unwrap private key %s (wrong passphrase?): %w", key.ID, err)
	}

	// The caller caches kek (keyUse.apply) only after the file authenticates
	// and its output is published, or zeroes it (keyUse.discard).
	return privateKey, func() { uc.kekProvider.ZeroKEK(privateKey) }, kek, nil
}

// keyPassphrasePrompt names the key, so that a user with several locked keys
// knows which passphrase to type (V2-6).
func keyPassphrasePrompt(key *entities.IdentityKey) string {
	name := key.ID
	if key.Alias != "" {
		name = key.Alias + " (" + key.ID + ")"
	}
	return "Enter passphrase or 24-word recovery phrase for key " + name + ": "
}

// trialKeyOrder returns the usable (non-expired) keys in the order the
// decryptor tries them: the default key first, then the others by use
// (UsageCount, highest first; the key store has no last-use time). The sort
// is stable, so equal counts keep the repository order (newest first).
func trialKeyOrder(keys []*entities.IdentityKey) []*entities.IdentityKey {
	usable := make([]*entities.IdentityKey, 0, len(keys))
	for _, key := range keys {
		if !key.IsExpired() {
			usable = append(usable, key)
		}
	}
	slices.SortStableFunc(usable, func(a, b *entities.IdentityKey) int {
		if a.IsDefault != b.IsDefault {
			if a.IsDefault {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.UsageCount, a.UsageCount)
	})
	return usable
}

// findRecipientKey resolves the CEK of a method-2 file and the local key that
// opened it (nil if a recovery phrase of a key that is not in the store did).
// Blocks name no recipient, so it tries each block with each usable local
// X25519 key in trialKeyOrder. Each private key is unlocked once (session
// cache or prompt). The first block that unwraps gives the CEK; the caller
// then verifies the header MAC with it, and records the key's usage only after
// the body authenticates. No block opens → ErrNotARecipient; if a local key
// could not be unlocked, that error is returned instead, because that key may
// be the recipient.
func (uc *DecryptFile) findRecipientKey(ctx context.Context, encFile *entities.EncryptedFile, recoveryPassphrase string) ([]byte, *keyUse, error) {
	blocks := make([]entities.DecodedRecipientBlock, 0, len(encFile.Recipients))
	for i, block := range encFile.Recipients {
		decoded, err := block.Decode()
		if err != nil {
			return nil, nil, fmt.Errorf("recipient block %d: %w", i, err)
		}
		blocks = append(blocks, decoded)
	}

	keys, err := uc.keyRepo.List(ctx, KeyFilters{Type: entities.KeyTypeX25519})
	if err != nil {
		return nil, nil, err
	}

	// A recovery phrase names exactly one private key: derive it once, try it
	// on every block, and credit the usage to the local key with the same
	// public key (if any), not to whichever key the loop reached first (V2-6).
	if priv, pub, ok, err := uc.mnemonicKey(recoveryPassphrase); err != nil {
		return nil, nil, err
	} else if ok {
		defer clear(priv)
		for _, b := range blocks {
			cek, err := uc.crypto.UnwrapCEK(b.WrappedCEK, b.EphemeralPubKey, b.Nonce, priv, []byte(entities.WrapCEKAAD))
			if err != nil {
				continue
			}
			for _, key := range keys {
				if subtle.ConstantTimeCompare(key.PublicKey, pub) == 1 {
					return cek, &keyUse{key: key}, nil
				}
			}
			return cek, nil, nil
		}
		return nil, nil, entities.ErrNotARecipient
	}

	candidates := uc.unlockedFirst(trialKeyOrder(keys), recoveryPassphrase)
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("%w: no usable local X25519 key", entities.ErrNotARecipient)
	}

	var unlockErr error
	for _, key := range candidates {
		privateKey, cleanup, freshKEK, err := uc.resolvePrivateKey(ctx, key, recoveryPassphrase)
		if err != nil {
			if unlockErr == nil {
				unlockErr = fmt.Errorf("key %s: %w", key.ID, err)
			}
			continue
		}
		for _, b := range blocks {
			cek, err := uc.crypto.UnwrapCEK(b.WrappedCEK, b.EphemeralPubKey, b.Nonce, privateKey, []byte(entities.WrapCEKAAD))
			if err == nil {
				cleanup()
				return cek, &keyUse{key: key, kek: freshKEK}, nil
			}
		}
		cleanup()
		if freshKEK != nil {
			uc.kekProvider.ZeroKEK(freshKEK)
		}
	}
	if unlockErr != nil {
		return nil, nil, unlockErr
	}
	return nil, nil, entities.ErrNotARecipient
}

// unlockedFirst moves keys with a cached KEK to the front (stable), so that a
// caller without a passphrase is prompted only when no unlocked key opens the
// file (V2-6). With a supplied passphrase the cache is not used, so the order
// stays as it is.
func (uc *DecryptFile) unlockedFirst(keys []*entities.IdentityKey, passphrase string) []*entities.IdentityKey {
	if passphrase != "" {
		return keys
	}
	cached := make([]*entities.IdentityKey, 0, len(keys))
	locked := make([]*entities.IdentityKey, 0, len(keys))
	for _, key := range keys {
		kek, err := uc.sessionStore.GetKEK(key.ID)
		if err == nil && kek != nil {
			uc.kekProvider.ZeroKEK(kek)
			cached = append(cached, key)
			continue
		}
		locked = append(locked, key)
	}
	return append(cached, locked...)
}

// mnemonicKey reports whether passphrase is a valid 24-word recovery phrase
// and, if so, returns the X25519 key pair derived from it.
func (uc *DecryptFile) mnemonicKey(passphrase string) (priv, pub []byte, ok bool, err error) {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(passphrase)))
	if len(words) != 24 {
		return nil, nil, false, nil
	}
	joined := strings.Join(words, " ")
	if !uc.crypto.IsValidMnemonic(joined) {
		return nil, nil, false, nil
	}
	pub, priv, err = uc.crypto.DeriveX25519FromMnemonic(joined)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to derive key from recovery phrase: %w", err)
	}
	return priv, pub, true, nil
}

// keyUse is the effect of a decryption on the key store: the usage counter of
// the local key that opened the file, and the KEK that this decryption
// unlocked (nil when it came from the cache or a recovery phrase). It is
// applied only after the file authenticates and (for a file) its output is
// published; otherwise it is discarded. A nil *keyUse is valid (method 3, or
// a recovery phrase of a key that is not in the store).
type keyUse struct {
	key *entities.IdentityKey
	kek []byte
}

// apply caches the unlocked KEK with the session store's TTL and increments
// the key's usage counter. Failures are logged: they must not fail a
// decryption that already succeeded.
func (u *keyUse) apply(ctx context.Context, uc *DecryptFile) {
	if u == nil || u.key == nil {
		return
	}
	if u.kek != nil {
		if err := uc.sessionStore.SetKEK(u.key.ID, u.kek, 0); err != nil {
			uc.logger.Warn("Failed to cache KEK for session", map[string]interface{}{"key_id": u.key.ID, "error": err.Error()})
		}
		uc.kekProvider.ZeroKEK(u.kek)
		u.kek = nil
	}
	u.key.IncrementUsage()
	if err := uc.keyRepo.Update(ctx, u.key); err != nil {
		uc.logger.Warn("Failed to record key usage", map[string]interface{}{"key_id": u.key.ID, "error": err.Error()})
	}
}

// discard zeroes the unlocked KEK without caching it.
func (u *keyUse) discard(uc *DecryptFile) {
	if u != nil && u.kek != nil {
		uc.kekProvider.ZeroKEK(u.kek)
		u.kek = nil
	}
}

// ProtectKeyStore names key databases (SQLite DSNs). No output of this
// usecase may go into a folder of one of them, with or without an explicit
// output path or Overwrite: the configured folder, the resolved (symlink)
// folder, or a folder with a hard link to the database (CheckOutputPath).
// It returns uc for chaining.
func (uc *DecryptFile) ProtectKeyStore(dsns ...string) *DecryptFile {
	uc.keyStores = append(uc.keyStores, dsns...)
	return uc
}
