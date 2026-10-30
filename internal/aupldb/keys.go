package aupldb

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// DefaultPublicKeys are the keys AUPLA signs its builds with. Readers pin
// them; rotating a key means adding the new one here before signing with it.
var DefaultPublicKeys = []ed25519.PublicKey{
	mustPublicKey("g4VjAgb1UB5/1YK2fjqcXoQFbrAQleiOsaX7h4Dvh4k="),
}

// KeyID is how a file names the key that signed it: the first 8 bytes of
// the key's SHA-256.
func KeyID(pub ed25519.PublicKey) [8]byte {
	sum := sha256.Sum256(pub)
	return [8]byte(sum[:8])
}

// ParsePublicKey reads a key in the form FormatPublicKey writes: the 32 raw
// bytes in standard base64.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("aupldb: %q is not a base64 Ed25519 public key", s)
	}
	return ed25519.PublicKey(b), nil
}

func FormatPublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

func mustPublicKey(s string) ed25519.PublicKey {
	k, err := ParsePublicKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// ParsePrivateKey reads a PEM "PRIVATE KEY" (PKCS #8) block holding an
// Ed25519 key, as MarshalPrivateKey and `openssl genpkey -algorithm ed25519`
// write.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("aupldb: no PEM PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("aupldb: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("aupldb: not an Ed25519 key")
	}
	return priv, nil
}

func MarshalPrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
