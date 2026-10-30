package config

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordLengthLimits(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"too short", "1234567", false},
		{"minimum", "12345678", true},
		{"past bcrypt's 72 bytes", strings.Repeat("a", 100), true},
		{"maximum", strings.Repeat("a", 256), true},
		{"too long", strings.Repeat("a", 257), false},
		{"multi-byte counts characters", strings.Repeat("é", 200), true}, // 400 bytes
	}
	for _, tt := range tests {
		if err := CheckPasswordLength(tt.pw); (err == nil) != tt.ok {
			t.Errorf("%s: CheckPasswordLength = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestLongPasswordsUseEveryCharacter(t *testing.T) {
	pw := strings.Repeat("x", 90) + "tail-one"
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, pw) {
		t.Fatal("a 98-character password does not verify against its own hash")
	}
	// Plain bcrypt would only see the first 72 bytes and accept this too.
	if CheckPassword(h, strings.Repeat("x", 90)+"tail-two") {
		t.Fatal("a password differing only after byte 72 was accepted")
	}
}

func TestShortPasswordHashesStayPlainBcrypt(t *testing.T) {
	// Hashes made before long passwords were allowed (plain bcrypt) must
	// still verify, and new short hashes must stay readable by plain bcrypt.
	old, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(string(old), "correct horse") {
		t.Fatal("an existing plain-bcrypt hash no longer verifies")
	}
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte("correct horse")) != nil {
		t.Fatal("a short password's new hash is not plain bcrypt")
	}
}

func TestHashPasswordRefusesBadLength(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrPasswordLength {
		t.Fatalf("HashPassword(short) error = %v, want ErrPasswordLength", err)
	}
}
