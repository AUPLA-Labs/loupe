package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Admin password limits, in characters. The upper bound only keeps request
// bodies small; it is not a bcrypt limit (see bcryptInput).
const (
	MinPasswordLen = 8
	MaxPasswordLen = 256
)

// ErrPasswordLength is the one message every password form shows.
var ErrPasswordLength = errors.New("password must be 8 to 256 characters")

// CheckPasswordLength enforces MinPasswordLen and MaxPasswordLen.
func CheckPasswordLength(pw string) error {
	if n := utf8.RuneCountInString(pw); n < MinPasswordLen || n > MaxPasswordLen {
		return ErrPasswordLength
	}
	return nil
}

// bcryptInput is what bcrypt sees for pw. bcrypt reads at most 72 bytes, so a
// longer password is first reduced to its SHA-256 (base64, 43 bytes) and every
// byte of it counts. Passwords of 72 bytes or fewer go in unchanged, so hashes
// made before long passwords were allowed still verify.
func bcryptInput(pw string) []byte {
	if len(pw) <= 72 {
		return []byte(pw)
	}
	sum := sha256.Sum256([]byte(pw))
	return []byte(base64.RawStdEncoding.EncodeToString(sum[:]))
}

// HashPassword checks pw's length and returns its bcrypt hash.
func HashPassword(pw string) (string, error) {
	if err := CheckPasswordLength(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword(bcryptInput(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword reports whether pw matches hash, made by HashPassword (or by
// plain bcrypt, for passwords of 72 bytes or fewer).
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), bcryptInput(pw)) == nil
}
