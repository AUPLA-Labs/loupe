package handler

import (
	"sort"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/admin"
)

// Event rollups keep repetitive traffic from flooding the events log. A
// cleared visitor using a web app (Nextcloud: scripts, styles, API polling,
// WebDAV) sends hundreds of requests a minute, and a client stuck on the
// rate limit keeps hammering it; one event per request buries everything
// else and pushes real verdicts out of the ring buffer.
//
// Instead, the first request of a run is logged on its own, so the live feed
// still shows a visitor arrive or a flood start. Further requests from the
// same client are counted and logged as one summary event (Event.Count)
// once the client has been quiet for rollupIdle, and at least every
// rollupMaxAge while it keeps going. A request the caller marks as notable
// (a cleared page navigation) is still logged on its own mid-run.
const (
	rollupIdle     = 5 * time.Minute
	rollupMaxAge   = 15 * time.Minute
	rollupTick     = 30 * time.Second
	rollupMaxRuns  = 10000 // open runs; beyond this, events are logged individually
	rollupMaxPaths = 200   // distinct paths tracked per run; the rest count as otherPath
	rollupTopPaths = 8     // paths kept on the summary event
	otherPath      = "(other paths)"
)

// rollupKey identifies a run. UA is part of it for cleared visitors, so
// devices sharing an address keep separate summaries; it is left empty for
// rate-limited floods, whose clients often rotate it. rules names the
// rules.yaml rules behind the request (the enforced one, then the log-only
// matches), so a run never mixes requests that different rules touched and
// per-rule counts stay right.
type rollupKey struct {
	action, reason, ip, host, ua, rules string
}

type rollupRun struct {
	lastSeen time.Time
	// The requests folded since the last summary: the template event (the
	// first of them), when they started and ended, and where they went.
	pending     *admin.Event
	since, last time.Time
	count       int
	methods     map[string]struct{}
	paths       map[string]int
}

type rollups struct {
	mu   sync.Mutex
	runs map[rollupKey]*rollupRun
	emit func(admin.Event)
	now  func() time.Time
}

func newRollups(emit func(admin.Event)) *rollups {
	return &rollups{runs: make(map[rollupKey]*rollupRun), emit: emit, now: time.Now}
}

// add records the request behind e under k. It is logged on its own when it
// starts a run or notable is set, and folded into the run's next summary
// otherwise.
func (r *rollups) add(k rollupKey, e admin.Event, notable bool) {
	now := r.now()
	r.mu.Lock()
	run, ok := r.runs[k]
	switch {
	case !ok && len(r.runs) >= rollupMaxRuns:
		r.mu.Unlock()
		r.emit(e)
		return
	case !ok:
		r.runs[k] = &rollupRun{lastSeen: now}
		r.mu.Unlock()
		r.emit(e)
		return
	}
	run.lastSeen = now
	if notable {
		r.mu.Unlock()
		r.emit(e)
		return
	}
	if run.pending == nil {
		run.pending, run.since = &e, now
		run.methods, run.paths = make(map[string]struct{}), make(map[string]int)
	}
	run.last = now
	run.count++
	run.methods[e.Method] = struct{}{}
	if _, seen := run.paths[e.Path]; seen || len(run.paths) < rollupMaxPaths {
		run.paths[e.Path]++
	} else {
		run.paths[otherPath]++
	}
	run.pending.BadIP = e.BadIP // latest feed status
	r.mu.Unlock()
}

// flush logs the summaries that are due: runs idle for rollupIdle (which
// then end) and runs that have been accumulating for rollupMaxAge. With
// all set, every pending summary is logged and every run ends (shutdown).
func (r *rollups) flush(all bool) {
	now := r.now()
	var out []admin.Event
	r.mu.Lock()
	for k, run := range r.runs {
		idle := now.Sub(run.lastSeen) >= rollupIdle
		if all || idle || (run.pending != nil && now.Sub(run.since) >= rollupMaxAge) {
			if run.pending != nil {
				out = append(out, run.summary(now))
				run.pending, run.count, run.methods, run.paths = nil, 0, nil, nil
			}
		}
		if all || idle {
			delete(r.runs, k)
		}
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	for _, e := range out {
		r.emit(e)
	}
}

// summary is the run's pending requests as one event, timestamped now so
// the log stays in time order.
func (run *rollupRun) summary(now time.Time) admin.Event {
	e := *run.pending
	e.Time, e.VID = now, ""
	e.Count, e.Since, e.Until = run.count, run.since, run.last
	if len(run.methods) > 1 {
		e.Method = ""
	}
	e.Paths = make([]admin.PathCount, 0, len(run.paths))
	for p, n := range run.paths {
		e.Paths = append(e.Paths, admin.PathCount{Path: p, Count: n})
	}
	sort.Slice(e.Paths, func(i, j int) bool {
		if e.Paths[i].Count != e.Paths[j].Count {
			return e.Paths[i].Count > e.Paths[j].Count
		}
		return e.Paths[i].Path < e.Paths[j].Path
	})
	if len(e.Paths) > rollupTopPaths {
		e.Paths = e.Paths[:rollupTopPaths]
	}
	e.Path = e.Paths[0].Path
	return e
}

// run flushes due summaries until stop is closed.
func (r *rollups) run(stop <-chan struct{}) {
	t := time.NewTicker(rollupTick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.flush(false)
		case <-stop:
			return
		}
	}
}
