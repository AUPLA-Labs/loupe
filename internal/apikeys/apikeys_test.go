package apikeys

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var anywhere = netip.MustParseAddr("198.51.100.7")

func newStore(t *testing.T) *Store {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "api_keys.yaml"))
}

func TestAPIKeyHashedAtRest(t *testing.T) {
	s := newStore(t)
	plain, k, err := s.Create(NewKey{Name: "partner"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, Prefix) || len(plain) != len(Prefix)+43 {
		t.Fatalf("key %q, want lpk_ and 32 bytes of base64url", plain)
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), plain[len(Prefix):]) {
		t.Fatal("the key itself is in the file")
	}
	if !strings.Contains(string(data), Hash(plain)) {
		t.Fatal("the key's hash is not in the file")
	}
	if fi, _ := os.Stat(s.Path()); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, want 0600", fi.Mode().Perm())
	}
	if id, res, _ := s.Check(plain, anywhere); res != Valid || id != k.ID {
		t.Fatalf("Check = %q %v, want valid %s", id, res, k.ID)
	}
	if _, res, _ := s.Check(plain+"x", anywhere); res != Unknown {
		t.Fatal("a different key was accepted")
	}
	// A second store reading the same file knows the key.
	if _, res, _ := New(s.Path()).Check(plain, anywhere); res != Valid {
		t.Fatal("the key didn't survive a reload")
	}
}

func TestAPIKeyCIDRRestriction(t *testing.T) {
	s := newStore(t)
	plain, _, err := s.Create(NewKey{Name: "office", CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]Result{
		"203.0.113.9":        Valid,
		"::ffff:203.0.113.9": Valid,
		"2001:db8::1":        Valid,
		"198.51.100.7":       WrongNet,
	} {
		if _, res, _ := s.Check(plain, netip.MustParseAddr(addr)); res != want {
			t.Errorf("from %s: %v, want %v", addr, res, want)
		}
	}
	if _, _, err := s.Create(NewKey{Name: "x", CIDRs: []string{"203.0.113.9/24"}}); err == nil {
		t.Error("a CIDR with host bits was accepted")
	}
}

func TestRevokedKeyRejectedImmediately(t *testing.T) {
	s := newStore(t)
	plain, k, _ := s.Create(NewKey{Name: "gone"})
	if _, ok, err := s.Revoke(k.ID); !ok || err != nil {
		t.Fatalf("Revoke = %v %v", ok, err)
	}
	if _, res, _ := s.Check(plain, anywhere); res != Unknown {
		t.Fatalf("revoked key: %v, want unknown", res)
	}
	if _, ok, _ := s.Revoke(k.ID); ok {
		t.Error("revoking twice reported a key")
	}
}

func TestPerKeyLimit(t *testing.T) {
	s := newStore(t)
	a, _, _ := s.Create(NewKey{Name: "a", Rate: 1, Burst: 2})
	b, _, _ := s.Create(NewKey{Name: "b"})
	for range 2 {
		if _, res, _ := s.Check(a, anywhere); res != Valid {
			t.Fatal("refused within the burst")
		}
	}
	if _, res, wait := s.Check(a, anywhere); res != OverLimit || wait <= 0 {
		t.Fatalf("3rd: %v %v, want over the limit with a wait", res, wait)
	}
	for range 10 {
		if _, res, _ := s.Check(b, anywhere); res != Valid {
			t.Fatal("a key without a rate was limited")
		}
	}
	// Issuing another key keeps the first one's counter.
	s.Create(NewKey{Name: "c"})
	if _, res, _ := s.Check(a, anywhere); res != OverLimit {
		t.Fatal("saving the file reset another key's limit")
	}
}

func TestLastUsedFlushedNotPerRequest(t *testing.T) {
	s := newStore(t)
	plain, _, _ := s.Create(NewKey{Name: "a"})
	before, _ := os.ReadFile(s.Path())
	s.Check(plain, anywhere)
	if after, _ := os.ReadFile(s.Path()); string(after) != string(before) {
		t.Fatal("a check wrote the file")
	}
	if s.List()[0].LastUsed == nil {
		t.Fatal("List doesn't show the last use")
	}
	s.Close()
	if after, _ := os.ReadFile(s.Path()); !strings.Contains(string(after), "last_used") {
		t.Fatal("Close didn't write the last use")
	}
}

func TestHandEditPickedUpAndBrokenFileKeepsKeys(t *testing.T) {
	s := newStore(t)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	plain, _, _ := s.Create(NewKey{Name: "a"})
	os.WriteFile(s.Path(), []byte("keys: [\n"), 0o600)
	os.Chtimes(s.Path(), clock.Add(time.Minute), clock.Add(time.Minute))
	clock = clock.Add(time.Minute)
	if _, res, _ := s.Check(plain, anywhere); res != Valid {
		t.Fatal("a broken file dropped the keys in force")
	}
	if s.LoadErr() == "" {
		t.Fatal("no load error for a broken file")
	}
	if _, _, err := s.Create(NewKey{Name: "b"}); err == nil {
		t.Fatal("Create wrote over a broken file")
	}
	os.WriteFile(s.Path(), []byte("keys: []\n"), 0o600)
	os.Chtimes(s.Path(), clock.Add(2*time.Minute), clock.Add(2*time.Minute))
	clock = clock.Add(time.Minute)
	if _, res, _ := s.Check(plain, anywhere); res != Unknown {
		t.Fatal("a key removed by hand still works")
	}
}
