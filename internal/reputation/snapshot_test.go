package reputation

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.json")

	s1 := New(testConfig())
	s1.Record("7.7.7.7", 6461, Webdriver)
	s1.Record("7.7.7.7", 6461, VerifyFailure)
	if err := s1.Snapshot(path); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	s2 := New(testConfig())
	if err := s2.Restore(path); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	want := s1.IPPressure("7.7.7.7")
	got := s2.IPPressure("7.7.7.7")
	if got < want-0.01 || got > want+0.01 {
		t.Errorf("IP pressure after restore = %v, want ~%v", got, want)
	}
	wantASN := s1.ASNPressure(6461)
	gotASN := s2.ASNPressure(6461)
	if gotASN < wantASN-0.01 || gotASN > wantASN+0.01 {
		t.Errorf("ASN pressure after restore = %v, want ~%v", gotASN, wantASN)
	}
}

func TestRestoreMissingFileIsNotAnError(t *testing.T) {
	s := New(testConfig())
	err := s.Restore(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Restore of a missing file should be a no-op, got: %v", err)
	}
}

func TestRestoreAppliesDecayForElapsedDowntime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.json")

	s1 := New(testConfig())
	s1.Record("8.8.8.8", 0, Webdriver) // +10
	// Simulate the snapshot having been written one half-life ago.
	s1.mu.Lock()
	s1.ip["8.8.8.8"].LastUpdate = time.Now().Add(-6 * time.Hour)
	s1.mu.Unlock()
	if err := s1.Snapshot(path); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	s2 := New(testConfig())
	if err := s2.Restore(path); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got := s2.IPPressure("8.8.8.8")
	if got > 5.1 || got < 4.9 {
		t.Fatalf("restored pressure should reflect one half-life of decay: got %v, want ~5", got)
	}
}
