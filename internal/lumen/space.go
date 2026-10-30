package lumen

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/scrypt"
)

// ErrBusy means every space check slot stayed taken for the whole wait.
var ErrBusy = errors.New("lumen: space verifier busy")

// spaceWait bounds how long an answer waits for a free slot before the
// verifier gives up and the page is asked to retry.
const spaceWait = 3 * time.Second

// Verifier recomputes proof-of-space answers. Unlike work, space costs the
// server as much to check as the client to solve, so only a bounded number
// of checks run at once: the worst case is slots × the memory ceiling.
type Verifier struct {
	slots chan struct{}
}

// NewVerifier returns a verifier running at most concurrent checks at once.
func NewVerifier(concurrent int) *Verifier {
	if concurrent < 1 {
		concurrent = 1
	}
	return &Verifier{slots: make(chan struct{}, concurrent)}
}

// CheckSpace reports whether a's digest is the scrypt of its work answers.
// Call it only after CheckWork has passed: the cheap check gates the
// expensive one, so an answer that didn't do the work costs the server
// nothing here.
func (v *Verifier) CheckSpace(ctx context.Context, c *Challenge, a Answer) (bool, error) {
	if c == nil || len(a.Digest) != 64 {
		return false, nil
	}
	got, err := hex.DecodeString(a.Digest)
	if err != nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, spaceWait)
	defer cancel()
	select {
	case v.slots <- struct{}{}:
	case <-ctx.Done():
		return false, ErrBusy
	}
	defer func() { <-v.slots }()
	want, err := Space(c.SpaceSalt, a.Numbers, c.LogN)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// Space computes the proof-of-space digest: scrypt(password = the work
// answers, salt = the challenge's space salt, N = 2^logN, r = R, p = 1),
// 32 bytes. proof.js's scrypt must match it byte for byte.
func Space(spaceSalt string, numbers []int64, logN uint8) ([]byte, error) {
	return scrypt.Key(SpacePassword(numbers), []byte(spaceSalt), 1<<logN, R, 1, 32)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
