package handler

import (
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/admin"
)

func testRollups() (*rollups, *[]admin.Event, *time.Time) {
	var got []admin.Event
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r := newRollups(func(e admin.Event) { got = append(got, e) })
	r.now = func() time.Time { return now }
	return r, &got, &now
}

func reqEvent(method, path string) admin.Event {
	return admin.Event{Action: "ALLOW", Reason: "clearance", IP: "1.2.3.4", Host: "cloud.example", Method: method, Path: path, VID: "v-" + path}
}

func TestRollupFoldsRepeatsIntoOneSummary(t *testing.T) {
	r, got, now := testRollups()
	k := rollupKey{"ALLOW", "clearance", "1.2.3.4", "cloud.example", "UA", ""}

	r.add(k, reqEvent("GET", "/apps/files/"), true) // starts the run: logged
	start := *now
	for i := 0; i < 5; i++ {
		*now = now.Add(time.Second)
		r.add(k, reqEvent("GET", "/app.js"), false)
	}
	*now = now.Add(time.Second)
	r.add(k, reqEvent("PROPFIND", "/remote.php/dav/"), false)
	*now = now.Add(time.Second)
	r.add(k, reqEvent("GET", "/apps/photos/"), true) // notable: logged at once
	last := *now

	if len(*got) != 2 || (*got)[1].Path != "/apps/photos/" {
		t.Fatalf("want the run start and the navigation logged, got %+v", *got)
	}
	r.flush(false)
	if len(*got) != 2 {
		t.Fatalf("summary logged before the run went idle")
	}

	*now = last.Add(rollupIdle)
	r.flush(false)
	if len(*got) != 3 {
		t.Fatalf("want a summary after %v idle, got %d events", rollupIdle, len(*got))
	}
	s := (*got)[2]
	if s.Count != 6 || s.Path != "/app.js" || s.Method != "" || s.VID != "" {
		t.Errorf("summary = count %d path %q method %q vid %q", s.Count, s.Path, s.Method, s.VID)
	}
	if !s.Since.Equal(start.Add(time.Second)) || s.Until.Before(s.Since) || !s.Time.Equal(*now) {
		t.Errorf("summary times since=%v until=%v t=%v", s.Since, s.Until, s.Time)
	}
	if len(s.Paths) != 2 || s.Paths[0] != (admin.PathCount{Path: "/app.js", Count: 5}) {
		t.Errorf("paths = %+v", s.Paths)
	}

	// The run ended, so the next request starts a new one and is logged.
	r.add(k, reqEvent("GET", "/x.css"), false)
	if len(*got) != 4 || (*got)[3].Count != 0 {
		t.Errorf("request after an idle gap not logged on its own: %+v", *got)
	}
}

func TestRollupSummarizesLongRunsPeriodically(t *testing.T) {
	r, got, now := testRollups()
	k := rollupKey{"LIMIT", "rate_limited", "1.2.3.4", "cloud.example", "", ""}
	r.add(k, reqEvent("GET", "/"), false)
	for i := 0; i < int(rollupMaxAge/time.Minute)+1; i++ {
		*now = now.Add(time.Minute)
		r.add(k, reqEvent("GET", "/"), false)
		r.flush(false)
	}
	if len(*got) != 2 || (*got)[1].Count != int(rollupMaxAge/time.Minute)+1 {
		t.Fatalf("want one summary after %v of continuous traffic, got %+v", rollupMaxAge, *got)
	}
	*now = now.Add(time.Minute)
	r.add(k, reqEvent("GET", "/"), false)
	if len(*got) != 2 {
		t.Errorf("ongoing run restarted after its summary")
	}
	r.flush(true)
	if len(*got) != 3 || (*got)[2].Count != 1 {
		t.Errorf("shutdown flush: %+v", *got)
	}
}

func TestEventN(t *testing.T) {
	if n := (&admin.Event{}).N(); n != 1 {
		t.Errorf("plain event N = %d", n)
	}
	if n := (&admin.Event{Count: 40}).N(); n != 40 {
		t.Errorf("summary N = %d", n)
	}
}
