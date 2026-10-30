package admin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

const (
	fakeHash   = "$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"
	fakeSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // 20 bytes, base32
)

// storeFixture is a store over a temp file with a clock the test controls.
type storeFixture struct {
	t     *testing.T
	path  string
	store *userStore
	clock time.Time
	mtime time.Time
}

func newStoreFixture(t *testing.T, users ...config.AdminUser) *storeFixture {
	t.Helper()
	f := &storeFixture{
		t:     t,
		path:  filepath.Join(t.TempDir(), "admin_auth.yaml"),
		clock: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		mtime: time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC),
	}
	if err := config.SaveAdminAuth(f.path, &config.AdminAuth{Users: users}); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	f.touch()
	f.store = newUserStore(f.path, users)
	f.store.now = func() time.Time { return f.clock }
	f.store.lastCheck = f.clock
	return f
}

// touch gives the file a new, distinct mtime, whatever the filesystem's
// timestamp precision.
func (f *storeFixture) touch() {
	f.t.Helper()
	f.mtime = f.mtime.Add(time.Minute)
	if err := os.Chtimes(f.path, f.mtime, f.mtime); err != nil {
		f.t.Fatal(err)
	}
}

// writeFile replaces the file as a hand edit would.
func (f *storeFixture) writeFile(body string) {
	f.t.Helper()
	if err := os.WriteFile(f.path, []byte(body), 0600); err != nil {
		f.t.Fatal(err)
	}
	f.touch()
}

func (f *storeFixture) writeUsers(users ...config.AdminUser) {
	f.t.Helper()
	if err := config.SaveAdminAuth(f.path, &config.AdminAuth{Users: users}); err != nil {
		f.t.Fatal(err)
	}
	f.touch()
}

func (f *storeFixture) advance(d time.Duration) { f.clock = f.clock.Add(d) }

func (f *storeFixture) fileUsers() []config.AdminUser {
	f.t.Helper()
	a, err := config.LoadAdminAuth(f.path)
	if err != nil {
		f.t.Fatalf("file on disk does not load: %v", err)
	}
	return a.Users
}

func adminUser(name string) config.AdminUser {
	return config.AdminUser{Username: name, PasswordHash: fakeHash, Role: config.RoleAdmin}
}

func names(users []config.AdminUser) string {
	var n []string
	for _, u := range users {
		n = append(n, u.Username)
	}
	return strings.Join(n, ",")
}

func TestStoreReloadsChangedFile(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	if _, ok := f.store.get("bob"); ok {
		t.Fatal("bob exists before the file changes")
	}
	f.writeUsers(adminUser("pat"), adminUser("bob"))
	f.advance(time.Second)
	if _, ok := f.store.get("bob"); !ok {
		t.Fatal("get(bob) did not see the user added to the file")
	}
	if got := names(f.store.list()); got != "bob,pat" {
		t.Errorf("list() = %q, want bob,pat (sorted)", got)
	}
}

func TestStoreReloadsSameMtimeDifferentSize(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	f.writeUsers(adminUser("pat"), adminUser("bob"))
	// Put the old mtime back, as a same-second rewrite would leave it.
	if err := os.Chtimes(f.path, f.store.mtime, f.store.mtime); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Second)
	if _, ok := f.store.get("bob"); !ok {
		t.Fatal("a rewrite with the same mtime but a different length was not noticed")
	}
}

func TestStoreThrottlesStat(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	f.writeUsers(adminUser("pat"), adminUser("bob"))
	f.advance(999 * time.Millisecond)
	if _, ok := f.store.get("bob"); ok {
		t.Fatal("file change seen before the throttle interval passed")
	}
	f.advance(time.Millisecond)
	if _, ok := f.store.get("bob"); !ok {
		t.Fatal("file change not seen once the throttle interval passed")
	}
}

func TestBrokenUsersFileKeepsLastGood(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	f.writeFile("users: [")
	f.advance(time.Second)
	if _, ok := f.store.get("pat"); !ok {
		t.Fatal("last good user lost after the file broke")
	}
	if msg := f.store.loadError(); !strings.Contains(msg, f.path) {
		t.Fatalf("loadError() = %q, want it to name %s", msg, f.path)
	}
	f.writeUsers(adminUser("pat"), adminUser("bob"))
	f.advance(time.Second)
	if _, ok := f.store.get("bob"); !ok {
		t.Error("fixed file not loaded")
	}
	if msg := f.store.loadError(); msg != "" {
		t.Errorf("loadError() = %q after the file was fixed, want empty", msg)
	}
}

func TestBrokenUsersFileLoggedOnce(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	var buf bytes.Buffer
	f.store.logf = func(format string, args ...any) { buf.WriteString("x") }
	f.writeFile("users: [")
	for i := 0; i < 3; i++ {
		f.advance(time.Second)
		f.store.get("pat")
	}
	// A second distinct breakage logs again; the same one touched again does not.
	f.writeFile("users: []")
	f.advance(time.Second)
	f.store.get("pat")
	f.touch()
	f.advance(time.Second)
	f.store.get("pat")
	if buf.Len() != 2 {
		t.Errorf("logged %d times, want 2 (once per distinct message)", buf.Len())
	}
}

func TestUpdateBuildsOnChangedFile(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	f.writeUsers(adminUser("pat"), adminUser("bob")) // CLI edit, inside the throttle window
	err := f.store.update(func(users []config.AdminUser) ([]config.AdminUser, error) {
		return append(users, adminUser("carol")), nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := names(f.fileUsers()); got != "pat,bob,carol" {
		t.Errorf("file users = %q, want pat,bob,carol", got)
	}
	if got := names(f.store.list()); got != "bob,carol,pat" {
		t.Errorf("memory users = %q, want bob,carol,pat", got)
	}
	// Our own write must not look like an outside change.
	f.advance(time.Second)
	if _, ok := f.store.get("carol"); !ok {
		t.Error("carol lost after the next reload check")
	}
}

func TestUpdateRefusesLastAdmin(t *testing.T) {
	f := newStoreFixture(t, adminUser("pat"))
	before, _ := os.ReadFile(f.path)
	err := f.store.update(func(users []config.AdminUser) ([]config.AdminUser, error) {
		users[0].Role = config.RoleViewer
		return users, nil
	})
	if err == nil || !strings.Contains(err.Error(), "at least one admin must remain") {
		t.Fatalf("update err = %v, want the last-admin error", err)
	}
	after, _ := os.ReadFile(f.path)
	if !bytes.Equal(before, after) {
		t.Error("file changed although the update was refused")
	}
	if u, _ := f.store.get("pat"); u.Role != config.RoleAdmin {
		t.Errorf("memory role = %q after a refused update, want admin", u.Role)
	}
}

func TestUpdateGivesFnADeepCopy(t *testing.T) {
	u := adminUser("pat")
	u.RecoveryHashes = []string{fakeHash, fakeHash + "x"}
	f := newStoreFixture(t, u)
	boom := errors.New("boom")
	err := f.store.update(func(users []config.AdminUser) ([]config.AdminUser, error) {
		users[0].Username = "mutated"
		users[0].RecoveryHashes[0] = "mutated"
		return nil, boom
	})
	if err != boom {
		t.Fatalf("update err = %v, want fn's error unchanged", err)
	}
	got, ok := f.store.get("pat")
	if !ok || got.RecoveryHashes[0] != fakeHash {
		t.Errorf("fn's edits leaked into the store: %+v", got)
	}
	// get hands out copies too.
	got.RecoveryHashes[1] = "mutated"
	if again, _ := f.store.get("pat"); again.RecoveryHashes[1] != fakeHash+"x" {
		t.Error("mutating a result of get changed the store")
	}
}

func TestUpdateMemoryOnlyStore(t *testing.T) {
	s := newUserStore("", []config.AdminUser{adminUser("pat")})
	err := s.update(func(users []config.AdminUser) ([]config.AdminUser, error) {
		return append(users, adminUser("bob")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(s.list()); got != "bob,pat" {
		t.Errorf("users = %q, want bob,pat", got)
	}
	err = s.update(func(users []config.AdminUser) ([]config.AdminUser, error) { return nil, nil })
	if err == nil {
		t.Error("memory-only update to no users was accepted")
	}
	if len(s.list()) != 2 {
		t.Error("refused update changed the users")
	}
}

func TestUseTOTPStepIsMonotonic(t *testing.T) {
	u := adminUser("pat")
	u.TOTPSecret = fakeSecret
	f := newStoreFixture(t, u)
	steps := []struct {
		step int64
		want error
	}{{10, nil}, {10, errCodeUsed}, {9, errCodeUsed}, {11, nil}}
	for _, tt := range steps {
		if err := f.store.useTOTPStep("pat", tt.step); err != tt.want {
			t.Fatalf("useTOTPStep(%d) = %v, want %v", tt.step, err, tt.want)
		}
	}
	if got := f.fileUsers()[0].TOTPLastStep; got != 11 {
		t.Errorf("file totp_last_step = %d, want 11", got)
	}
	if err := f.store.useTOTPStep("nobody", 99); err != errNoUser {
		t.Errorf("unknown user: err = %v, want errNoUser", err)
	}
}

func TestConsumeRecoveryOnce(t *testing.T) {
	u := adminUser("pat")
	for i := 0; i < 10; i++ {
		u.RecoveryHashes = append(u.RecoveryHashes, fakeHash+string(rune('a'+i)))
	}
	f := newStoreFixture(t, u)
	h := fakeHash + "c"
	left, err := f.store.consumeRecovery("pat", h)
	if err != nil || left != 9 {
		t.Fatalf("consumeRecovery = %d, %v; want 9, nil", left, err)
	}
	if _, err := f.store.consumeRecovery("pat", h); err != errCodeUsed {
		t.Errorf("second consume err = %v, want errCodeUsed", err)
	}
	if got := len(f.fileUsers()[0].RecoveryHashes); got != 9 {
		t.Errorf("file holds %d recovery hashes, want 9", got)
	}
	if _, err := f.store.consumeRecovery("nobody", h); err != errNoUser {
		t.Errorf("unknown user: err = %v, want errNoUser", err)
	}
}

func TestStoreConcurrentUse(t *testing.T) {
	u := adminUser("pat")
	for i := 0; i < 20; i++ {
		u.RecoveryHashes = append(u.RecoveryHashes, fakeHash+string(rune('a'+i)))
	}
	f := newStoreFixture(t, u)
	// The same step claimed by many goroutines must succeed exactly once.
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.store.get("pat")
			if f.store.useTOTPStep("pat", 5) == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Errorf("step claimed %d times, want once", won)
	}
}

// breakers put the users file in the two states the store must not overwrite.
var breakers = []struct {
	name   string
	break_ func(f *storeFixture)
}{
	{"broken", func(f *storeFixture) { f.writeFile("users: [") }},
	{"missing", func(f *storeFixture) {
		if err := os.Remove(f.path); err != nil {
			f.t.Fatal(err)
		}
	}},
}

// fileBytes returns the file's contents, or nil if it doesn't exist.
func (f *storeFixture) fileBytes() []byte {
	b, _ := os.ReadFile(f.path)
	return b
}

func TestUpdateWithBrokenFileKeepsFile(t *testing.T) {
	for _, tt := range breakers {
		t.Run(tt.name, func(t *testing.T) {
			f := newStoreFixture(t, adminUser("pat"))
			tt.break_(f)
			before := f.fileBytes()
			err := f.store.update(func(users []config.AdminUser) ([]config.AdminUser, error) {
				return append(users, adminUser("bob")), nil
			})
			if err == nil || !strings.HasPrefix(err.Error(), "users file is broken, fix it or run loupe -setup-admin: ") ||
				!strings.Contains(err.Error(), f.path) {
				t.Fatalf("update err = %v, want the broken-file refusal naming the path", err)
			}
			if after := f.fileBytes(); !bytes.Equal(before, after) {
				t.Errorf("file changed from %q to %q although the update was refused", before, after)
			}
			if f.store.loadError() == "" {
				t.Error("loadError() cleared although the file is still broken")
			}
			if got := names(f.store.list()); got != "pat" {
				t.Errorf("users = %q after a refused update, want pat", got)
			}
		})
	}
}

func TestSignInCodesWorkWithBrokenFile(t *testing.T) {
	for _, tt := range breakers {
		t.Run(tt.name, func(t *testing.T) {
			u := adminUser("pat")
			u.TOTPSecret = fakeSecret
			u.RecoveryHashes = []string{fakeHash + "a", fakeHash + "b"}
			f := newStoreFixture(t, u)
			tt.break_(f)
			before := f.fileBytes()

			if err := f.store.useTOTPStep("pat", 10); err != nil {
				t.Fatalf("useTOTPStep(10) = %v, want ok while the file is broken", err)
			}
			if err := f.store.useTOTPStep("pat", 10); err != errCodeUsed {
				t.Errorf("replayed useTOTPStep(10) = %v, want errCodeUsed", err)
			}
			left, err := f.store.consumeRecovery("pat", fakeHash+"a")
			if err != nil || left != 1 {
				t.Fatalf("consumeRecovery = %d, %v; want 1, nil", left, err)
			}
			if _, err := f.store.consumeRecovery("pat", fakeHash+"a"); err != errCodeUsed {
				t.Errorf("replayed consumeRecovery = %v, want errCodeUsed", err)
			}
			if after := f.fileBytes(); !bytes.Equal(before, after) {
				t.Errorf("file changed from %q to %q", before, after)
			}
			if f.store.loadError() == "" {
				t.Error("loadError() cleared although the file is still broken")
			}
		})
	}
}
