package admin

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var rfcSecret = []byte("12345678901234567890")

func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	tests := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tt := range tests {
		if got := totpCode(rfcSecret, tt.unix/30); got != tt.want {
			t.Errorf("totpCode at T=%d = %q, want %q", tt.unix, got, tt.want)
		}
	}
}

func TestTOTPAcceptsAdjacentStep(t *testing.T) {
	now := time.Unix(1234567890, 0)
	step := now.Unix() / 30
	tests := []struct {
		offset int64
		ok     bool
	}{
		{-2, false}, {-1, true}, {0, true}, {1, true}, {2, false},
	}
	for _, tt := range tests {
		got, ok := checkTOTP(rfcSecret, totpCode(rfcSecret, step+tt.offset), now, 0)
		if ok != tt.ok {
			t.Errorf("step%+d: ok = %v, want %v", tt.offset, ok, tt.ok)
		}
		if ok && got != step+tt.offset {
			t.Errorf("step%+d: returned step %d, want %d", tt.offset, got, step+tt.offset)
		}
	}
}

func TestTOTPRejectsReplay(t *testing.T) {
	now := time.Unix(1234567890, 0)
	n := now.Unix() / 30
	code := totpCode(rfcSecret, n)
	if _, ok := checkTOTP(rfcSecret, code, now, n); ok {
		t.Error("a code for the last used step was accepted again")
	}
	if _, ok := checkTOTP(rfcSecret, code, now, n+1); ok {
		t.Error("a code for an older step than the last used one was accepted")
	}
	if step, ok := checkTOTP(rfcSecret, code, now, n-1); !ok || step != n {
		t.Errorf("a code for a newer step was refused: step=%d ok=%v", step, ok)
	}
}

func TestTOTPAcceptsSpacedCode(t *testing.T) {
	now := time.Unix(59, 0)
	tests := []struct {
		code string
		ok   bool
	}{
		{"287082", true},
		{"287 082", true},
		{" 287082 ", true},
		{"28708", false},
		{"2870822", false},
		{"28708a", false},
		{"", false},
	}
	for _, tt := range tests {
		if _, ok := checkTOTP(rfcSecret, tt.code, now, 0); ok != tt.ok {
			t.Errorf("checkTOTP(%q) ok = %v, want %v", tt.code, ok, tt.ok)
		}
	}
}

func TestTOTPSecretRoundTrip(t *testing.T) {
	b, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 20 {
		t.Fatalf("secret is %d bytes, want 20", len(b))
	}
	enc := encodeTOTPSecret(b)
	if strings.Contains(enc, "=") {
		t.Errorf("encoded secret %q has padding", enc)
	}
	for _, s := range []string{enc, strings.ToLower(enc), strings.ToLower(enc[:4]) + " " + enc[4:]} {
		got, err := decodeTOTPSecret(s)
		if err != nil || string(got) != string(b) {
			t.Errorf("decodeTOTPSecret(%q) = %x, %v; want %x", s, got, err, b)
		}
	}
}

func TestOTPAuthURI(t *testing.T) {
	got := otpauthURI("a b", rfcSecret)
	want := "otpauth://totp/Loupe:a%20b?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Loupe&algorithm=SHA1&digits=6&period=30"
	if got != want {
		t.Errorf("otpauthURI = %q, want %q", got, want)
	}
}

func TestRecoveryCodeNormalised(t *testing.T) {
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("got %d codes and %d hashes, want 10 of each", len(codes), len(hashes))
	}
	shape := regexp.MustCompile(`^[a-z2-7]{5}-[a-z2-7]{5}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !shape.MatchString(c) {
			t.Errorf("code %q does not match xxxxx-xxxxx", c)
		}
		if seen[c] {
			t.Errorf("code %q issued twice", c)
		}
		seen[c] = true
	}
	typed := strings.ToUpper(strings.ReplaceAll(codes[3], "-", ""))
	if h, ok := matchRecoveryCode(hashes, typed); !ok || h != hashes[3] {
		t.Errorf("upper-case code without dash: hash=%q ok=%v, want hash 3", h, ok)
	}
	if h, ok := matchRecoveryCode(hashes, codes[3]); !ok || h != hashes[3] {
		t.Errorf("code as shown: hash=%q ok=%v, want hash 3", h, ok)
	}
	if _, ok := matchRecoveryCode(hashes, "aaaaa-aaaaa"); ok {
		t.Error("a made-up code matched")
	}
}
