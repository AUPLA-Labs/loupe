package reputation

import (
	"testing"
	"time"
)

func TestBlockEventIncrements(t *testing.T) {
	for ev, want := range map[Event]float64{
		ScannerUA:    5,
		ClientUA:     1,
		SpoofedBot:   5,
		ExploitProbe: 8,
	} {
		s := New(testConfig())
		s.RecordIPOnce("7.7.7.7", ev, time.Minute)
		if got := s.IPPressure("7.7.7.7"); got != want {
			t.Errorf("event %d: pressure = %v, want %v", ev, got, want)
		}
	}
}

func TestRecordIPOnceThrottlesPerEvent(t *testing.T) {
	s := New(testConfig())
	if !s.RecordIPOnce("7.7.7.7", ScannerUA, time.Minute) {
		t.Fatal("first record should apply")
	}
	if s.RecordIPOnce("7.7.7.7", ScannerUA, time.Minute) {
		t.Fatal("a repeat within the window should be skipped")
	}
	// A different event, or a different IP, is not throttled by it.
	if !s.RecordIPOnce("7.7.7.7", ExploitProbe, time.Minute) {
		t.Fatal("a different event should apply")
	}
	if !s.RecordIPOnce("8.8.8.8", ScannerUA, time.Minute) {
		t.Fatal("a different IP should apply")
	}
	if got := s.IPPressure("7.7.7.7"); got != 13 {
		t.Fatalf("pressure = %v, want 13 (5 scanner + 8 exploit)", got)
	}
}

func TestRecordIPOnceAppliesAgainAfterWindow(t *testing.T) {
	s := New(testConfig())
	s.RecordIPOnce("7.7.7.7", ClientUA, time.Nanosecond)
	time.Sleep(time.Millisecond)
	if !s.RecordIPOnce("7.7.7.7", ClientUA, time.Nanosecond) {
		t.Fatal("a record after the window should apply")
	}
}

func TestRecordIPOnceNeverTouchesASN(t *testing.T) {
	s := New(testConfig())
	s.RecordIPOnce("7.7.7.7", ExploitProbe, time.Minute)
	if len(s.TopPressured(0)) != 1 {
		t.Fatalf("only the IP should hold pressure, got %+v", s.TopPressured(0))
	}
}
