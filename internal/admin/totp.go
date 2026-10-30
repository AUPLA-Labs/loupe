package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	totpStep       = 30 * time.Second
	totpDigits     = 6
	recoveryAlpha  = "abcdefghijklmnopqrstuvwxyz234567"
	recoveryLen    = 10
	recoveryNumber = 10
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpCode is the RFC 6238 code (HMAC-SHA1, 6 digits) for one 30-second step.
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	digits := [totpDigits]byte{}
	for i := totpDigits - 1; i >= 0; i-- {
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[:])
}

// newTOTPSecret returns 20 random bytes, the size RFC 4226 recommends.
func newTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func encodeTOTPSecret(b []byte) string { return totpEncoding.EncodeToString(b) }

// decodeTOTPSecret accepts the secret as an authenticator app shows it: any
// case, with spaces between groups.
func decodeTOTPSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	return totpEncoding.DecodeString(s)
}

// checkTOTP reports whether code is valid at now, allowing one step of clock
// drift either way. Only a step after lastStep is accepted, so a code works
// once; the matched step is returned for the caller to store as the new lastStep.
func checkTOTP(secret []byte, code string, now time.Time, lastStep int64) (step int64, ok bool) {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	cur := now.Unix() / int64(totpStep/time.Second)
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(code), []byte(totpCode(secret, s))) == 1 && s > lastStep {
			return s, true
		}
	}
	return 0, false
}

// otpauthURI is the key URI authenticator apps read from a QR code.
func otpauthURI(account string, secret []byte) string {
	return "otpauth://totp/Loupe:" + url.PathEscape(account) +
		"?secret=" + encodeTOTPSecret(secret) +
		"&issuer=Loupe&algorithm=SHA1&digits=6&period=30"
}

// newRecoveryCodes returns 10 single-use codes shown as xxxxx-xxxxx, and the
// bcrypt hash of each (hashes[i] belongs to codes[i]).
func newRecoveryCodes() (codes, hashes []string, err error) {
	for i := 0; i < recoveryNumber; i++ {
		b := make([]byte, recoveryLen)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		for j := range b {
			b[j] = recoveryAlpha[b[j]&31] // 32 symbols, so no modulo bias
		}
		code := string(b[:5]) + "-" + string(b[5:])
		h, err := bcrypt.GenerateFromPassword([]byte(normalizeRecovery(code)), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, string(h))
	}
	return codes, hashes, nil
}

// normalizeRecovery lower-cases a typed code and drops dashes and spaces.
func normalizeRecovery(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(s))
}

// matchRecoveryCode returns the hash that code matches. It checks every hash
// so the time taken doesn't reveal which position matched.
func matchRecoveryCode(hashes []string, code string) (hash string, ok bool) {
	code = normalizeRecovery(code)
	if len(code) != recoveryLen {
		return "", false
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			hash, ok = h, true
		}
	}
	return hash, ok
}
