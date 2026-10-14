package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// A vault seals saved device credentials for storage.
//
// What is sealed is h1 = SHA256(password||salt) — the per-device login
// credential the RustDesk client itself caches, not the password anyone typed.
// Because the salt differs per device, one sealed value opens exactly one
// device even when every device shares a password.
//
// The key comes from RDGUI_SECRET_KEY, deliberately not from the data volume
// and not derived from anything in it. That is the whole point: a copy of the
// database — a backup, a stolen volume, a snapshot — is not enough to recover
// any device credential. It is not protection against someone who already has
// the running host, who can read the environment and the process either way.
//
// A zero vault is valid and disabled: the feature is simply off until a key is
// configured, which is why every call checks enabled() rather than assuming.
type vault struct {
	key []byte // nil when no key is configured
}

var errVaultDisabled = errors.New("no RDGUI_SECRET_KEY is configured")

// newVault parses a base64 32-byte key. An empty string yields a disabled
// vault, which is a supported configuration rather than an error.
func newVault(keyB64 string) (*vault, error) {
	if keyB64 == "" {
		return &vault{}, nil
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("RDGUI_SECRET_KEY is not valid base64: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("RDGUI_SECRET_KEY must decode to %d bytes, got %d",
			chacha20poly1305.KeySize, len(key))
	}
	return &vault{key: key}, nil
}

func (v *vault) enabled() bool { return v != nil && len(v.key) == chacha20poly1305.KeySize }

// seal encrypts plaintext for peerID.
//
// peerID is authenticated as additional data rather than encrypted, so a box
// moved to another device's row fails to open instead of silently handing that
// device a credential that was never meant for it.
func (v *vault) seal(peerID, plaintext string) ([]byte, error) {
	if !v.enabled() {
		return nil, errVaultDisabled
	}
	aead, err := chacha20poly1305.NewX(v.key)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generating nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, []byte(plaintext), []byte(peerID)), nil
}

// open reverses seal. It fails on a wrong key, a tampered box, or a box stored
// under a different device.
func (v *vault) open(peerID string, box []byte) (string, error) {
	if !v.enabled() {
		return "", errVaultDisabled
	}
	aead, err := chacha20poly1305.NewX(v.key)
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	if len(box) < aead.NonceSize() {
		return "", errors.New("vault: sealed value is truncated")
	}
	nonce, ct := box[:aead.NonceSize()], box[aead.NonceSize():]
	out, err := aead.Open(nil, nonce, ct, []byte(peerID))
	if err != nil {
		return "", fmt.Errorf("vault: cannot open sealed value: %w", err)
	}
	return string(out), nil
}

// GenerateSecretKey mints a key for RDGUI_SECRET_KEY.
func GenerateSecretKey() (string, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating secret key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
