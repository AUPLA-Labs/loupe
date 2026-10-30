package underattack

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func TestUnderAttackExpires(t *testing.T) {
	u := New(filepath.Join(t.TempDir(), "ua.json"))
	clock := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	u.now = func() time.Time { return clock }
	if u.Floor() != tier.Pass {
		t.Fatal("on before being turned on")
	}
	if _, err := u.Set(true, time.Hour, "", true, "pat"); err != nil {
		t.Fatal(err)
	}
	if u.Floor() != tier.SingleClick {
		t.Fatalf("floor %v, want the default single_click", u.Floor())
	}
	if since, ok := u.RevokesIssuedBefore(); !ok || !since.Equal(clock) {
		t.Fatalf("RevokesIssuedBefore = %v %v", since, ok)
	}
	clock = clock.Add(time.Hour)
	if u.Floor() != tier.Pass || u.State().Enabled {
		t.Fatal("still on after its hour")
	}
	if _, ok := u.RevokesIssuedBefore(); ok {
		t.Fatal("still revoking after its hour")
	}
}

func TestUnderAttackSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ua.json")
	u := New(path)
	u.Set(true, 0, "prism", false, "pat")
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	again := New(path)
	if again.Floor() != tier.Prism || again.State().By != "pat" {
		t.Fatalf("after reload: floor %v state %+v", again.Floor(), again.State())
	}
	os.WriteFile(path, []byte("{broken"), 0o600)
	if New(path).Floor() != tier.Pass {
		t.Fatal("a broken file isn't treated as off")
	}
}

func TestTurningOnAgainKeepsStart(t *testing.T) {
	u := New(filepath.Join(t.TempDir(), "ua.json"))
	clock := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	u.now = func() time.Time { return clock }
	u.Set(true, 0, "", true, "a")
	clock = clock.Add(10 * time.Minute)
	u.Set(true, time.Hour, "prism", true, "b")
	if since, _ := u.RevokesIssuedBefore(); !since.Equal(clock.Add(-10 * time.Minute)) {
		t.Fatalf("since %v: changing the settings moved the start, revoking clearances earned meanwhile", since)
	}
	if _, err := u.Set(true, 0, "pulse", false, "a"); err == nil {
		t.Fatal("an unknown tier was accepted")
	}
}
