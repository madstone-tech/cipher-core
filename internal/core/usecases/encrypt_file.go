package usecases

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/term"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// streamingThreshold is the file size at which file encryption switches to the
// chunked stream framing (≥ threshold) rather than the in-memory single frame.
const streamingThreshold = 1 << 20 // 1 MiB

// EncryptFileRequest contains parameters for file encryption
type EncryptFileRequest struct {
	FilePath       string
	RecipientEmail string      // For X25519 encryption to a CKD-resolved recipient
	Recipients     []Recipient // For multi-recipient encryption
	Passphrase     string      // For passphrase-based encryption
	OutputPath     string      // Optional, defaults to <FilePath>.mdstn. An explicit path replaces a file (never the input).
	Overwrite      bool        // Allows the default path to replace an existing file
	JSONOutput     bool        // When true, skip interactive prompt and return mnemonic in response
}

// EncryptStreamRequest contains the parameters of EncryptFile.EncryptStream.
// Exactly one intent: Recipients, RecipientEmail, or Passphrase; none of them
// means "for me" (the default key, created on first use).
type EncryptStreamRequest struct {
	Recipients       []Recipient
	RecipientEmail   string
	Passphrase       string
	OriginalFilename string // stored in the header; optional
	JSONOutput       bool   // see EncryptFileRequest.JSONOutput
}

// EncryptFileResponse contains the result of encryption
type EncryptFileResponse struct {
	OutputPath       string // empty for EncryptStream
	Method           entities.EncryptionMethod
	Fingerprint      string
	RecoveryMnemonic string // Non-empty only on first run with JSONOutput=true
}

// EncryptFile encrypts a file using the appropriate method
type EncryptFile struct {
	keyRepo      KeyRepository
	recoveryRepo RecoveryKeyRepository
	crypto       CryptoEngine
	kekProvider  KEKProvider
	sessionStore SessionStore
	encoder      FileEncoder
	lookupKeyUC  *LookupKey
	fileHandler  FileHandler
	progress     ProgressReporter
	prompter     UserPrompter
	logger       Logger
	keyStores    []string // key database DSNs whose files no output may replace
}

// NewEncryptFile creates a new EncryptFile usecase
func NewEncryptFile(
	keyRepo KeyRepository,
	recoveryRepo RecoveryKeyRepository,
	crypto CryptoEngine,
	kekProvider KEKProvider,
	sessionStore SessionStore,
	encoder FileEncoder,
	lookupKeyUC *LookupKey,
	fileHandler FileHandler,
	progress ProgressReporter,
	prompter UserPrompter,
	logger Logger,
) *EncryptFile {
	return &EncryptFile{
		keyRepo:      keyRepo,
		recoveryRepo: recoveryRepo,
		crypto:       crypto,
		kekProvider:  kekProvider,
		sessionStore: sessionStore,
		encoder:      encoder,
		lookupKeyUC:  lookupKeyUC,
		fileHandler:  fileHandler,
		progress:     progress,
		prompter:     prompter,
		logger:       logger,
	}
}

// contentPlan is a resolved encryption intent: the container header with the
// method fields set, the content key that seals the body, and the result.
type contentPlan struct {
	file    *entities.EncryptedFile
	key     []byte
	resp    *EncryptFileResponse
	success string                // progress message on success
	usedKey *entities.IdentityKey // local key whose usage counter to bump
}

// zero clears the content key.
func (p *contentPlan) zero() { clear(p.key) }

// Execute encrypts req.FilePath to a container (version 0x03). Files of 1 MiB or
// more use the stream framing through EncryptStream, ReadStream, and a
// StagedWriter; smaller files use the single-frame framing. Both framings use
// the same header, KDF, and recipient rules (FR-027).
func (uc *EncryptFile) Execute(ctx context.Context, req *EncryptFileRequest) (*EncryptFileResponse, error) {
	if req.FilePath == "" {
		return nil, entities.ErrInvalidInput
	}
	// An explicitly empty (non-nil) Recipients list is a caller error — reject it
	// rather than silently falling through to self/passphrase encryption, which
	// would encrypt to a key the caller never chose (per the format spec, an
	// empty recipient list must be rejected at encryption time).
	if req.Recipients != nil && len(req.Recipients) == 0 {
		return nil, entities.ErrNoRecipients
	}

	outputPath, exclusive, err := uc.CheckOutput(req)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat input file: %w", err)
	}
	sreq := &EncryptStreamRequest{
		Recipients:       req.Recipients,
		RecipientEmail:   req.RecipientEmail,
		Passphrase:       req.Passphrase,
		OriginalFilename: localOriginalFilename(req.FilePath),
		JSONOutput:       req.JSONOutput,
	}

	var plan *contentPlan
	if info.Size() >= streamingThreshold {
		plan, err = uc.encryptFileStream(ctx, req.FilePath, outputPath, exclusive, sreq)
	} else {
		plan, err = uc.encryptFileSingleFrame(ctx, req.FilePath, outputPath, exclusive, sreq)
	}
	if err != nil {
		return nil, err
	}

	uc.progress.ReportSuccess(plan.success)
	plan.resp.OutputPath = outputPath
	return plan.resp, nil
}

// encryptFileStream encrypts inputPath to outputPath with the stream framing.
// Nothing appears at outputPath unless the whole stream succeeds.
func (uc *EncryptFile) encryptFileStream(ctx context.Context, inputPath, outputPath string, exclusive bool, req *EncryptStreamRequest) (*contentPlan, error) {
	reader, err := uc.fileHandler.ReadStream(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input stream: %w", err)
	}
	defer reader.Close() //nolint:errcheck // best-effort: read-only close

	writer, err := openOutput(uc.fileHandler, outputPath, exclusive)
	if err != nil {
		return nil, err
	}
	plan, err := uc.encryptStream(ctx, reader, writer, req)
	if err != nil {
		return nil, errors.Join(err, writer.Abort())
	}
	if err := commitOutput(ctx, writer); err != nil {
		return nil, err
	}
	// Count the key's use only once the output is published (T-7).
	uc.recordKeyUse(ctx, plan)
	return plan, nil
}

// encryptFileSingleFrame encrypts inputPath (< 1 MiB) with the single-frame
// framing: [header][header_mac(32)][body_nonce(12)][ciphertext+tag], header
// bytes as AAD, in one atomic write.
func (uc *EncryptFile) encryptFileSingleFrame(ctx context.Context, inputPath, outputPath string, exclusive bool, req *EncryptStreamRequest) (*contentPlan, error) {
	uc.progress.ReportProgress("Reading file...", 20)
	plaintext, err := uc.fileHandler.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	plan, err := uc.planContent(ctx, req)
	if err != nil {
		return nil, err
	}
	defer plan.zero()

	uc.progress.ReportProgress("Encrypting...", 50)
	plan.file.Chunked = false
	plan.file.OriginalFilename = req.OriginalFilename
	plan.file.EncryptedAt = time.Now()
	headerBytes, err := uc.encoder.EncodeHeader(plan.file)
	if err != nil {
		return nil, err
	}
	headerMAC, payloadKey, err := uc.sealHeader(plan.key, headerBytes)
	if err != nil {
		return nil, err
	}
	defer clear(payloadKey)
	ciphertext, bodyNonce, err := uc.crypto.EncryptAES(plaintext, payloadKey, headerBytes)
	if err != nil {
		return nil, entities.ErrEncryptionFailed
	}

	out := make([]byte, 0, len(headerBytes)+len(headerMAC)+len(bodyNonce)+len(ciphertext))
	out = append(out, headerBytes...)
	out = append(out, headerMAC...)
	out = append(out, bodyNonce...)
	out = append(out, ciphertext...)

	uc.progress.ReportProgress("Writing encrypted file...", 80)
	writer, err := openOutput(uc.fileHandler, outputPath, exclusive)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(out); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to write file: %w", err), writer.Abort())
	}
	if err := commitOutput(ctx, writer); err != nil {
		return nil, err
	}
	uc.recordKeyUse(ctx, plan)
	return plan, nil
}

// EncryptStream reads all of src and writes one chunked container
// (chunked=true) to dst: the header, the header MAC, then the stream body
// sealed with the payload key and the header bytes as AAD. On error dst can
// hold a partial container; the caller MUST discard it. The response has no
// OutputPath.
func (uc *EncryptFile) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, req *EncryptStreamRequest) (*EncryptFileResponse, error) {
	if err := entities.ValidOriginalFilename(req.OriginalFilename); err != nil {
		return nil, fmt.Errorf("%w: %w", entities.ErrInvalidInput, err)
	}
	plan, err := uc.encryptStream(ctx, src, dst, req)
	if err != nil {
		return nil, err
	}
	uc.recordKeyUse(ctx, plan)
	return plan.resp, nil
}

// encryptStream is the EncryptStream core; it also returns the plan so the
// file path can report the method-specific success message.
func (uc *EncryptFile) encryptStream(ctx context.Context, src io.Reader, dst io.Writer, req *EncryptStreamRequest) (*contentPlan, error) {
	plan, err := uc.planContent(ctx, req)
	if err != nil {
		return nil, err
	}
	defer plan.zero()

	uc.progress.ReportProgress("Encrypting (streaming)...", 50)
	plan.file.Chunked = true
	plan.file.OriginalFilename = req.OriginalFilename
	plan.file.EncryptedAt = time.Now()
	headerBytes, err := uc.encoder.EncodeHeader(plan.file)
	if err != nil {
		return nil, err
	}
	headerMAC, payloadKey, err := uc.sealHeader(plan.key, headerBytes)
	if err != nil {
		return nil, err
	}
	defer clear(payloadKey)
	if _, err := dst.Write(headerBytes); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := dst.Write(headerMAC); err != nil {
		return nil, fmt.Errorf("failed to write header MAC: %w", err)
	}
	if err := uc.crypto.EncryptStream(ctx, src, dst, payloadKey, headerBytes); err != nil {
		return nil, fmt.Errorf("streaming encryption failed: %w", err)
	}
	return plan, nil
}

// sealHeader returns the header MAC of headerBytes and the payload key for
// the file key (docs/format-spec.md §Key schedule).
func (uc *EncryptFile) sealHeader(fileKey, headerBytes []byte) (headerMAC, payloadKey []byte, err error) {
	if headerMAC, err = uc.crypto.HeaderMAC(fileKey, headerBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to compute header MAC: %w", err)
	}
	if payloadKey, err = uc.crypto.DerivePayloadKey(fileKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive payload key: %w", err)
	}
	return headerMAC, payloadKey, nil
}

// recordKeyUse bumps the usage counter of the local key that the file was
// encrypted for (encrypt for self).
func (uc *EncryptFile) recordKeyUse(ctx context.Context, plan *contentPlan) {
	if plan.usedKey == nil {
		return
	}
	plan.usedKey.IncrementUsage()
	if err := uc.keyRepo.Update(ctx, plan.usedKey); err != nil {
		uc.logger.Warn("Failed to record key usage", map[string]interface{}{"key_id": plan.usedKey.ID, "error": err.Error()})
	}
}

// planContent resolves the encryption intent of req to a content plan.
func (uc *EncryptFile) planContent(ctx context.Context, req *EncryptStreamRequest) (*contentPlan, error) {
	if req.Recipients != nil && len(req.Recipients) == 0 {
		return nil, entities.ErrNoRecipients
	}
	switch {
	case len(req.Recipients) > 0:
		uc.progress.ReportProgress(fmt.Sprintf("Encrypting for %d recipients...", len(req.Recipients)), 40)
		plan, err := uc.planRecipients(req.Recipients)
		if err != nil {
			return nil, err
		}
		plan.success = fmt.Sprintf("File encrypted for %d recipients", len(req.Recipients))
		return plan, nil
	case req.RecipientEmail != "":
		return uc.planForEmail(ctx, req.RecipientEmail)
	case req.Passphrase != "":
		return uc.planPassphrase(req.Passphrase)
	default:
		return uc.planForSelf(ctx, req.JSONOutput)
	}
}

// planRecipients checks every recipient key (canonical X25519, FR-004), then
// generates a random CEK and wraps it to each recipient: one block per
// recipient. Blocks carry no fingerprint hint or key ID. Every encryption
// path (raw key, local key, CKD lookup, SDK, MCP) reaches this check.
func (uc *EncryptFile) planRecipients(recipients []Recipient) (*contentPlan, error) {
	if len(recipients) == 0 {
		return nil, entities.ErrNoRecipients
	}
	if len(recipients) > entities.MaxRecipients {
		return nil, entities.ErrTooManyRecipients
	}
	for i, recipient := range recipients {
		if err := uc.crypto.ValidatePublicKey(recipient.PublicKey); err != nil {
			return nil, fmt.Errorf("recipient %d (%s): %w", i+1, recipient.Fingerprint, err)
		}
	}
	cek, err := uc.crypto.GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}
	blocks := make([]entities.RecipientBlock, 0, len(recipients))
	for _, recipient := range recipients {
		ephemeralPubKey, wrapNonce, wrappedCEK, err := uc.crypto.WrapCEK(cek, recipient.PublicKey, []byte(entities.WrapCEKAAD))
		if err != nil {
			clear(cek)
			return nil, fmt.Errorf("failed to wrap CEK for recipient %s: %w", recipient.Fingerprint, err)
		}
		blocks = append(blocks, entities.RecipientBlock{
			EphemeralPubKey: base64.StdEncoding.EncodeToString(ephemeralPubKey),
			Nonce:           base64.StdEncoding.EncodeToString(wrapNonce),
			WrappedCEK:      base64.StdEncoding.EncodeToString(wrappedCEK),
		})
	}
	return &contentPlan{
		file: &entities.EncryptedFile{
			Version:    entities.FormatVersion,
			Method:     entities.MethodX25519,
			Recipients: blocks,
		},
		key:  cek,
		resp: &EncryptFileResponse{Method: entities.MethodX25519},
	}, nil
}

// planForEmail resolves the recipient's public key via the LookupKey usecase
// (cache → network → cache) and plans one recipient block for it.
func (uc *EncryptFile) planForEmail(ctx context.Context, email string) (*contentPlan, error) {
	uc.progress.ReportProgress("Looking up recipient's public key...", 10)
	lookupResp, err := uc.lookupKeyUC.Execute(ctx, &LookupKeyRequest{Email: email})
	if err != nil {
		uc.logger.Error("CKD lookup failed", map[string]interface{}{
			"email": email,
			"error": err.Error(),
		})
		return nil, entities.ErrCKDLookupFailed
	}
	uc.progress.ReportProgress("Encrypting for recipient...", 40)
	plan, err := uc.planRecipients([]Recipient{{PublicKey: lookupResp.PublicKey, Fingerprint: lookupResp.Fingerprint}})
	if err != nil {
		return nil, err
	}
	plan.resp.Fingerprint = lookupResp.Fingerprint
	plan.success = "File encrypted for " + email
	return plan, nil
}

// planForSelf plans one recipient block for the default key, which is
// created on first use (zero-config).
func (uc *EncryptFile) planForSelf(ctx context.Context, jsonOutput bool) (*contentPlan, error) {
	uc.progress.ReportProgress("Loading default key...", 10)
	var recoveryMnemonic string
	key, err := uc.keyRepo.GetDefault(ctx)
	if err != nil {
		if !errors.Is(err, entities.ErrNotFound) {
			return nil, err
		}
		uc.progress.ReportProgress("Generating default encryption key...", 20)
		key, recoveryMnemonic, err = uc.createDefaultKey(ctx, jsonOutput)
		if err != nil {
			return nil, err
		}
	}
	plan, err := uc.planRecipients([]Recipient{{PublicKey: key.PublicKey, Fingerprint: key.Fingerprint}})
	if err != nil {
		return nil, err
	}
	plan.resp.Fingerprint = key.Fingerprint
	plan.resp.RecoveryMnemonic = recoveryMnemonic
	plan.usedKey = key
	plan.success = "File encrypted successfully"
	return plan, nil
}

// planPassphrase derives the method-3 file key: Argon2id with the fixed
// parameters (entities.FileKDFParams) and a fresh 16-byte salt, both stored
// in the header that the header MAC authenticates.
func (uc *EncryptFile) planPassphrase(passphrase string) (*contentPlan, error) {
	salt := make([]byte, entities.FileSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	uc.progress.ReportProgress("Deriving file key...", 30)
	key, err := uc.crypto.DeriveFileKeyArgon2id(passphrase, salt)
	if err != nil {
		return nil, entities.ErrEncryptionFailed
	}
	return &contentPlan{
		file: &entities.EncryptedFile{
			Version:   entities.FormatVersion,
			Method:    entities.MethodPassphrase,
			Salt:      salt,
			KDF:       entities.KDFArgon2id,
			KDFParams: entities.FileKDFParams,
		},
		key: key,
		// No fingerprint: any value derived from the password (for example
		// its SHA-256) would let an attacker test passwords without Argon2id.
		resp:    &EncryptFileResponse{Method: entities.MethodPassphrase},
		success: "File encrypted with passphrase",
	}, nil
}

// createDefaultKey generates a default X25519 keypair and, on the very first run
// (recoveryRepo.Count == 0), initiates the BIP39 recovery phrase flow.
// It returns the new key and (in JSON mode only) the recovery mnemonic string.
func (uc *EncryptFile) createDefaultKey(ctx context.Context, jsonOutput bool) (*entities.IdentityKey, string, error) {
	publicKey, privateKey, err := uc.crypto.GenerateX25519Keypair()
	if err != nil {
		return nil, "", err
	}

	fingerprint := uc.crypto.Hash(publicKey)
	id := fingerprint[:16]

	// Wrap the private key if KEKProvider is available
	wrappedKey := privateKey
	var salt []byte
	if uc.kekProvider != nil {
		passphrase, promptErr := uc.prompter.PromptPassphrase("Enter key passphrase for new key: ")
		if promptErr != nil {
			return nil, "", fmt.Errorf("failed to read key passphrase: %w", promptErr)
		}
		if len(passphrase) == 0 {
			return nil, "", fmt.Errorf("key passphrase must not be empty")
		}
		salt, err = uc.kekProvider.GenerateSalt()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate salt: %w", err)
		}
		kek, deriveErr := uc.kekProvider.DeriveKEK(passphrase, salt)
		if deriveErr != nil {
			return nil, "", fmt.Errorf("failed to derive KEK: %w", deriveErr)
		}
		wrappedKey, err = uc.kekProvider.WrapKey(privateKey, kek, id)
		if err != nil {
			uc.kekProvider.ZeroKEK(kek)
			return nil, "", fmt.Errorf("failed to wrap private key: %w", err)
		}
		// Cache KEK and zero raw key
		if err := uc.sessionStore.SetKEK(id, kek, 0); err != nil {
			uc.logger.Warn("Failed to cache KEK for session", map[string]interface{}{"key_id": id, "error": err.Error()})
		}
		uc.kekProvider.ZeroKEK(kek)
		uc.kekProvider.ZeroKEK(privateKey)
	}

	key := &entities.IdentityKey{
		ID:                id,
		Type:              entities.KeyTypeX25519,
		Alias:             "default",
		Fingerprint:       fingerprint,
		PublicKey:         publicKey,
		WrappedPrivateKey: wrappedKey,
		Argon2idSalt:      salt,
		CreatedAt:         time.Now(),
		IsDefault:         true,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	if err := uc.keyRepo.Create(ctx, key); err != nil {
		return nil, "", err
	}

	uc.progress.ReportSuccess(fmt.Sprintf("Created default encryption key (fingerprint: %s...)", fingerprint[:8]))

	uc.logger.Info("Created default encryption key", map[string]interface{}{
		"key_id":      key.ID,
		"fingerprint": key.Fingerprint,
	})

	// Initiate recovery phrase flow on first ever run.
	count, err := uc.recoveryRepo.Count(ctx)
	if err != nil {
		return nil, "", err
	}

	if count == 0 {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate BIP39 entropy: %w", err)
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate BIP39 mnemonic: %w", err)
		}

		_, capturedMnemonic, err := uc.generateRecoveryPhrase(ctx, mnemonic, jsonOutput)

		// Zero the mnemonic bytes before checking error.
		mnemonicBytes := []byte(mnemonic)
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}

		if err != nil {
			return nil, "", err
		}

		return key, capturedMnemonic, nil
	}

	return key, "", nil
}

// generateRecoveryPhrase derives and stores the Argon2id salt from a BIP39 mnemonic.
// In JSON mode it skips the interactive prompt and returns the mnemonic to the caller.
// In interactive mode it displays a warning, prompts for confirmation, then zeroes the mnemonic.
// It returns (salt, capturedMnemonic, err); capturedMnemonic is non-empty only in JSON mode.
func (uc *EncryptFile) generateRecoveryPhrase(ctx context.Context, mnemonic string, jsonOutput bool) ([]byte, string, error) {
	if jsonOutput {
		keyBytes, salt, err := uc.crypto.DeriveKeyArgon2id(mnemonic)
		if err != nil {
			return nil, "", fmt.Errorf("failed to derive recovery key: %w", err)
		}

		for i := range keyBytes {
			keyBytes[i] = 0
		}

		rk := &entities.RecoveryKey{
			ID:        uc.crypto.Hash(salt)[:16],
			Salt:      salt,
			CreatedAt: time.Now(),
		}
		if err := uc.recoveryRepo.Create(ctx, rk); err != nil {
			return nil, "", fmt.Errorf("failed to store recovery key: %w", err)
		}

		return salt, mnemonic, nil
	}

	// Interactive mode — require a TTY.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, "", fmt.Errorf("recovery phrase confirmation requires an interactive terminal or --json flag")
	}

	words := strings.Fields(mnemonic)
	grid := formatMnemonicGrid(words)

	fmt.Println()
	fmt.Println("⚠ IMPORTANT: Recovery Phrase")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Write down the following 24 words in order and store them")
	fmt.Println("securely. This phrase will NOT be shown again. You will")
	fmt.Println("need it to recover your encrypted files if you lose access")
	fmt.Println("to this device.")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Print(grid)
	fmt.Println()

	for {
		answer, err := uc.prompter.PromptString("Have you written down your recovery phrase? (yes/no): ")
		if err != nil {
			return nil, "", entities.ErrRecoveryAborted
		}

		if strings.EqualFold(strings.TrimSpace(answer), "yes") {
			break
		}

		// Re-display grid and re-prompt.
		fmt.Println()
		fmt.Print(grid)
		fmt.Println()
	}

	keyBytes, salt, err := uc.crypto.DeriveKeyArgon2id(mnemonic)
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive recovery key: %w", err)
	}

	for i := range keyBytes {
		keyBytes[i] = 0
	}

	rk := &entities.RecoveryKey{
		ID:        uc.crypto.Hash(salt)[:16],
		Salt:      salt,
		CreatedAt: time.Now(),
	}
	if err := uc.recoveryRepo.Create(ctx, rk); err != nil {
		return nil, "", fmt.Errorf("failed to store recovery key: %w", err)
	}

	return salt, "", nil
}

// formatMnemonicGrid formats 24 BIP39 words into a 4-column × 6-row grid.
func formatMnemonicGrid(words []string) string {
	const cols = 4

	var sb strings.Builder

	for i, word := range words {
		fmt.Fprintf(&sb, "%2d. %-10s", i+1, word)
		if (i+1)%cols == 0 {
			sb.WriteByte('\n')
		} else {
			sb.WriteString("  ")
		}
	}

	return sb.String()
}

// localOriginalFilename returns the base name of a local input file for the
// header, or "" when that name is not a safe base name (for example a name
// with ':' or a control character): a decryptor would reject such a header.
func localOriginalFilename(path string) string {
	name := filepath.Base(path)
	if entities.ValidOriginalFilename(name) != nil {
		return ""
	}
	return name
}

// ProtectKeyStore names key databases (SQLite DSNs). No output of this
// usecase may go into a folder of one of them, with or without an explicit
// output path or Overwrite: the configured folder, the resolved (symlink)
// folder, or a folder with a hard link to the database (CheckOutputPath).
// It returns uc for chaining.
func (uc *EncryptFile) ProtectKeyStore(dsns ...string) *EncryptFile {
	uc.keyStores = append(uc.keyStores, dsns...)
	return uc
}

// CheckOutput resolves the output path of req and checks it before any work
// (no prompt, no CKD lookup, no KDF): the input file, a key database folder, a
// directory, and, for the default path, an existing file (unless Overwrite)
// are refused. The CLI calls it before it resolves recipients or asks for a
// password (T-7); Execute calls it again, and the publish step stays the
// authoritative no-replace check.
func (uc *EncryptFile) CheckOutput(req *EncryptFileRequest) (outputPath string, exclusive bool, err error) {
	outputPath = req.OutputPath
	if outputPath == "" {
		outputPath, exclusive = req.FilePath+".mdstn", !req.Overwrite
	}
	if err := CheckOutputPath(uc.fileHandler, req.FilePath, outputPath, uc.keyStores); err != nil {
		return "", false, err
	}
	if exclusive {
		if err := refuseExisting(uc.fileHandler, outputPath); err != nil {
			return "", false, err
		}
	}
	return outputPath, exclusive, nil
}
