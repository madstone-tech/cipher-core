package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// Server implements the MCP protocol for Cipher
type Server struct {
	keyRepo      usecases.IdentityKeyRepository
	recoveryRepo usecases.RecoveryKeyRepository
	ckdCache     usecases.CKDCacheRepository
	cryptoEngine usecases.CryptoEngine
	kekProvider  usecases.KEKProvider
	sessionStore usecases.SessionStore
	encoder      usecases.FileEncoder
	ckdClient    usecases.CKDClient
	fileHandler  usecases.FileHandler
	logger       usecases.Logger
	dbPath       string // key database: no tool output may replace it
}

// NewServer creates a new MCP server
func NewServer(dbPath string) (*Server, error) {
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		return nil, err
	}

	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	recoveryRepo := sqlite.NewRecoveryKeyRepository(keyRepo.DB())
	cryptoEngine := crypto.NewEngine()
	kekProvider := crypto.NewArgon2idKEKProvider()
	sessionStore := crypto.NewInMemorySessionStore(context.Background())
	encoder := crypto.NewFileEncoder()
	ckdClient := ckd.NewClient(ckdCache)
	fileHandler := cli.NewFileHandler()
	logger := logging.NewSimpleLogger()

	return &Server{
		keyRepo:      keyRepo,
		recoveryRepo: recoveryRepo,
		ckdCache:     ckdCache,
		cryptoEngine: cryptoEngine,
		kekProvider:  kekProvider,
		sessionStore: sessionStore,
		encoder:      encoder,
		ckdClient:    ckdClient,
		fileHandler:  fileHandler,
		logger:       logger,
		dbPath:       dbPath,
	}, nil
}

// Tool represents an MCP tool
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ListTools returns available MCP tools
func (s *Server) ListTools() []Tool {
	return []Tool{
		{
			Name:        "encrypt_file",
			Description: "Encrypt a file to <file_path>.mdstn (X25519 recipient or file password). Never replaces an existing file.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path":  map[string]string{"type": "string", "description": "Path to file to encrypt"},
					"passphrase": map[string]string{"type": "string", "description": "Optional passphrase for encryption"},
					"for_email":  map[string]string{"type": "string", "description": "Optional recipient email for CKD lookup"},
				},
				"required": []string{"file_path"},
			},
		},
		{
			Name:        "decrypt_file",
			Description: "Decrypt a .mdstn file to its path without .mdstn (else <file_path>.decrypted). The sender's file name in the header is returned, never used as a path. Never replaces an existing file.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path":           map[string]string{"type": "string", "description": "Path to .mdstn file"},
					"passphrase":          map[string]string{"type": "string", "description": "Optional passphrase if encrypted with one (file-password mode)"},
					"recovery_passphrase": map[string]string{"type": "string", "description": "Optional recovery passphrase for KEK unwrapping (headless mode)"},
				},
				"required": []string{"file_path"},
			},
		},
		{
			Name:        "list_keys",
			Description: "List all encryption keys",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "export_key",
			Description: "Export the public part of a key (id, type, fingerprint, public key) in the result. Writes no file.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"key_id": map[string]string{"type": "string", "description": "ID of key to export"},
				},
				"required": []string{"key_id"},
			},
		},
		{
			Name:        "get_status",
			Description: "Get Cipher status and configuration",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "lookup_key",
			Description: "Look up a public key by email via CKD",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"email": map[string]string{"type": "string", "description": "Email to look up"},
				},
				"required": []string{"email"},
			},
		},
		{
			Name:        "import_key",
			Description: "Import a public key from base64",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"public_key": map[string]string{"type": "string", "description": "Base64-encoded public key"},
					"alias":      map[string]string{"type": "string", "description": "Alias for imported key"},
					"type":       map[string]string{"type": "string", "description": "Key type (default: x25519)"},
				},
				"required": []string{"public_key"},
			},
		},
	}
}

// CallTool executes an MCP tool
//
// A panic inside a tool handler becomes an error, so one malformed call never
// stops the MCP process (R-5).
func (s *Server) CallTool(ctx context.Context, name string, args map[string]interface{}) (result interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("tool %s failed: internal error: %v", name, r)
		}
	}()
	switch name {
	case "encrypt_file":
		return s.encryptFile(ctx, args)
	case "decrypt_file":
		return s.decryptFile(ctx, args)
	case "list_keys":
		return s.listKeys(ctx, args)
	case "export_key":
		return s.exportKey(ctx, args)
	case "get_status":
		return s.getStatus(ctx, args)
	case "lookup_key":
		return s.lookupKey(ctx, args)
	case "import_key":
		return s.importKey(ctx, args)
	default:
		return nil, fmt.Errorf("%w: %s", errUnknownTool, name)
	}
}

func (s *Server) encryptFile(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filePath, err := requiredString(args, "file_path")
	if err != nil {
		return nil, err
	}
	passphrase, _ := args["passphrase"].(string)
	forEmail, _ := args["for_email"].(string)

	progress := &noopProgress{}
	prompter := &noopPrompter{}
	lookupKeyUC := usecases.NewLookupKey(s.ckdClient, s.ckdCache, s.logger)
	encryptUC := usecases.NewEncryptFile(s.keyRepo, s.recoveryRepo, s.cryptoEngine, s.kekProvider, s.sessionStore, s.encoder, lookupKeyUC, s.fileHandler, progress, prompter, s.logger).
		ProtectKeyStore(s.dbPath)

	resp, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:       filePath,
		Passphrase:     passphrase,
		RecipientEmail: forEmail,
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"output_path": resp.OutputPath,
		"method":      resp.Method,
		"fingerprint": resp.Fingerprint,
	}, nil
}

func (s *Server) decryptFile(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	filePath, err := requiredString(args, "file_path")
	if err != nil {
		return nil, err
	}
	passphrase, _ := args["passphrase"].(string)
	recoveryPassphrase, _ := args["recovery_passphrase"].(string)

	progress := &noopProgress{}
	prompter := &noopPrompter{}
	decryptUC := usecases.NewDecryptFile(s.keyRepo, s.cryptoEngine, s.kekProvider, s.sessionStore, s.encoder, s.fileHandler, progress, prompter, s.logger).
		ProtectKeyStore(s.dbPath)

	resp, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:           filePath,
		Passphrase:         passphrase,
		RecoveryPassphrase: recoveryPassphrase,
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"output_path": resp.OutputPath,
		"method":      resp.Method,
	}, nil
}

func (s *Server) listKeys(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keys, err := s.keyRepo.ListMetadata(ctx, usecases.KeyFilters{})
	if err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, len(keys))
	for i, key := range keys {
		result[i] = map[string]interface{}{
			"id":          key.ID,
			"alias":       key.Alias,
			"type":        key.Type,
			"fingerprint": key.Fingerprint,
			"created_at":  key.CreatedAt,
		}
	}

	return map[string]interface{}{"keys": result}, nil
}

func (s *Server) exportKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID, err := requiredString(args, "key_id")
	if err != nil {
		return nil, err
	}

	// The export goes into the tool result. A tool that writes to a path the
	// caller (or a prompt injection) chooses can replace any file, the key
	// database included (S-1).
	foundKey, err := s.keyRepo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("key not found")
	}
	return map[string]interface{}{
		"id":          foundKey.ID,
		"type":        foundKey.Type,
		"fingerprint": foundKey.Fingerprint,
		"public_key":  base64.StdEncoding.EncodeToString(foundKey.PublicKey),
	}, nil
}

func (s *Server) getStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keys, err := s.keyRepo.ListMetadata(ctx, usecases.KeyFilters{})
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	return map[string]interface{}{
		"version":   "0.1.0",
		"key_count": len(keys),
		"status":    "ready",
	}, nil
}

type noopProgress struct{}

func (p *noopProgress) ReportProgress(message string, percent int) {}
func (p *noopProgress) ReportError(err error)                      {}
func (p *noopProgress) ReportSuccess(message string)               {}

type noopPrompter struct{}

func (p *noopPrompter) PromptString(prompt string) (string, error)     { return "", nil }
func (p *noopPrompter) PromptConfirm(prompt string) (bool, error)      { return false, nil }
func (p *noopPrompter) PromptPassphrase(prompt string) (string, error) { return "", nil }

func (s *Server) lookupKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	email, err := requiredString(args, "email")
	if err != nil {
		return nil, err
	}

	lookupUC := usecases.NewLookupKey(s.ckdClient, s.ckdCache, s.logger)
	resp, err := lookupUC.Execute(ctx, &usecases.LookupKeyRequest{Email: email})
	if err != nil {
		// A failed lookup is a tool failure (isError), not a result (T-5).
		return nil, fmt.Errorf("lookup of %s failed: %w", email, err)
	}

	source := "network"
	if resp.FromCache {
		source = "cache"
	}

	return map[string]interface{}{
		"found":             true,
		"email":             email,
		"fingerprint":       resp.Fingerprint,
		"key_type":          "x25519",
		"public_key_base64": base64.StdEncoding.EncodeToString(resp.PublicKey),
		"source":            source,
		"from_cache":        resp.FromCache,
	}, nil
}

func (s *Server) importKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pubKeyB64, err := requiredString(args, "public_key")
	if err != nil {
		return nil, err
	}
	alias, _ := args["alias"].(string)
	keyType, _ := args["type"].(string)
	if keyType == "" {
		keyType = "x25519"
	}
	if keyType != "x25519" {
		return nil, fmt.Errorf("unsupported key type: %s (supported: x25519)", keyType)
	}
	if alias == "" {
		alias = "imported"
	}

	pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key: %w", err)
	}
	if keyType == "x25519" && len(pubKey) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key: expected 32 bytes, got %d", len(pubKey))
	}

	fingerprint := s.cryptoEngine.Hash(pubKey)
	keyID := fingerprint[:16]

	key := &entities.IdentityKey{
		ID:             keyID,
		Type:           entities.KeyType(keyType),
		Alias:          alias,
		Fingerprint:    fingerprint,
		PublicKey:      pubKey,
		StorageMode:    entities.StorageModeAdvanced,
		StorageBackend: entities.StorageBackendSQLite,
	}
	key.CreatedAt = time.Now()

	if err := s.keyRepo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("import key failed: %w", err)
	}

	return map[string]interface{}{
		"key_id":      keyID,
		"fingerprint": fingerprint,
		"alias":       alias,
	}, nil
}

// requiredString returns the non-empty string argument key, or an error that
// matches entities.ErrInvalidInput. Tool arguments come from the MCP host (or
// a prompt injection), so a missing or wrongly typed value is a usage error.
func requiredString(args map[string]interface{}, key string) (string, error) {
	v, ok := args[key].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("%w: argument %q must be a non-empty string", entities.ErrInvalidInput, key)
	}
	return v, nil
}
