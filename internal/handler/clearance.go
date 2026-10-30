package handler

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/cookie"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

// Clearance-cookie revalidation. Without it a valid cookie would be a bearer
// pass for its whole lifetime: solve once in a browser, then scrape with any
// HTTP client sending the same UA. Every cleared request is checked against
// what the cookie recorded about the client it was issued to, and each cookie
// gets a request budget (abuse.clearance_budget; by default 300 documents and
// 3000 requests per 10 minutes, far beyond human browsing).

const (
	// shapeLoopWindow bounds how long a repeated shape mismatch is
	// remembered for the loop guard in checkClearance.
	shapeLoopWindow = 10 * time.Minute
)

// clearanceState holds revoked cookie IDs and the shape-loop guard.
type clearanceState struct {
	mu      sync.Mutex
	revoked map[string]time.Time // cookie ID → cookie expiry
	shapes  map[string]shapeMiss // client key → last shape mismatch
}

type shapeMiss struct {
	pair string // issued shape + ">" + observed shape
	id   string // cookie ID it was observed on
	at   time.Time
}

func newClearanceState() *clearanceState {
	s := &clearanceState{revoked: make(map[string]time.Time), shapes: make(map[string]shapeMiss)}
	go s.evictLoop()
	return s
}

// revoke rejects id until the cookie would have expired anyway.
func (s *clearanceState) revoke(id string, until time.Time) {
	s.mu.Lock()
	s.revoked[id] = until
	s.mu.Unlock()
}

func (s *clearanceState) isRevoked(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.revoked[id]
	return ok && time.Now().Before(until)
}

// shapeLoop records a shape mismatch and reports whether it is the browser
// loop rather than a different client: the same issued→observed mismatch
// recurring on a different, freshly issued cookie from the same client key.
// A browser whose probe fetch and navigations differ in shape hits that on
// its second cookie; a client replaying one copied cookie never does,
// because the cookie ID stays the same, and every fresh cookie costs a
// real pulse pass.
func (s *clearanceState) shapeLoop(key, pair, id string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.shapes[key]
	if ok && prev.pair == pair && prev.id != id && now.Sub(prev.at) < shapeLoopWindow {
		return true
	}
	s.shapes[key] = shapeMiss{pair: pair, id: id, at: now}
	return false
}

func (s *clearanceState) evictLoop() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		s.mu.Lock()
		for id, until := range s.revoked {
			if now.After(until) {
				delete(s.revoked, id)
			}
		}
		for k, m := range s.shapes {
			if now.Sub(m.at) > shapeLoopWindow {
				delete(s.shapes, k)
			}
		}
		s.mu.Unlock()
	}
}

// checkClearance returns why r may not use clearance c, if anything.
// hostile means the evidence points at a different client holding the
// cookie, rather than the browser it was issued to having changed.
//
// Every header check compares the request with the client's own behaviour
// at issuance, never with an absolute expectation, so a browser that never
// sent a header family is never penalised for not sending it.
func (h *Handler) checkClearance(r *http.Request, c cookie.Clearance) (reasons []string, hostile bool) {
	if h.clearance.isRevoked(c.ID) {
		return []string{"clearance_revoked"}, false
	}
	// Under attack with revoke_clearance: a clearance from before the switch
	// was turned on is earned again, once.
	if since, ok := h.underAttack.RevokesIssuedBefore(); ok && h.cookies.Issued(c).Before(since) {
		return []string{"clearance_under_attack"}, false
	}

	// Browsers attach Fetch Metadata to every request to a secure origin,
	// subresources included, so this holds on any request — except Safari's
	// service worker script fetches (registration and update checks), which
	// carry "Service-Worker: script" but no Fetch Metadata. Treating those as
	// a hand-off revoked the cookie on every Nextcloud page load on iOS.
	if c.HadSecFetch && r.Header.Get("Sec-Fetch-Site") == "" && !isServiceWorkerScript(r) {
		return []string{"clearance_sec_fetch_missing"}, true
	}

	// The client-hint and shape checks only run on navigations: it is less
	// certain that every subresource type (media, beacons) carries every
	// hint, and a wrongly dropped cookie there would break the page with
	// 403s instead of a silent re-pulse.
	doc := isDocumentNavigation(r)
	if doc {
		if c.HadCHUA && r.Header.Get("Sec-CH-UA") == "" {
			return []string{"clearance_sec_ch_ua_missing"}, true
		}
		if shape := cookie.ShapeOf(r); shape != c.Shape {
			if h.clearance.shapeLoop(h.ipKey(r), c.Shape+">"+shape, c.ID) {
				log.Printf("ALLOW clearance_shape_loop ip=%s ua=%q", h.ipKey(r), r.UserAgent())
			} else {
				return []string{"clearance_shape_changed"}, false
			}
		}
	}

	allOK := h.clearanceAllRL.Allow(c.ID)
	docOK := !doc || h.clearanceDocRL.Allow(c.ID)
	if !allOK || !docOK {
		return []string{"clearance_budget_exceeded"}, true
	}
	return nil, false
}

// dropClearance expires the cookie on this response. Hostile evidence also
// revokes the cookie ID, so a copy held elsewhere stops working, and records
// pressure; a changed browser costs only a silent re-pulse.
func (h *Handler) dropClearance(w http.ResponseWriter, r *http.Request, c cookie.Clearance, reasons []string, hostile bool) {
	ipKey := h.ipKey(r)
	h.cookies.Clear(w, r)
	// Logged in the dashboard's existing vocabulary: a revocation is a
	// failed clearance, a recheck is followed by a fresh challenge. The
	// clearance_* reason tells them apart from other FAIL/CHALLENGE events.
	action := "CHALLENGE"
	if hostile {
		action = "FAIL"
		h.clearance.revoke(c.ID, c.Expiry)
		asnNum, _, _ := h.clientASN(r)
		h.reputation.Record(ipKey, asnNum, reputation.ClearanceAbuse)
	}
	log.Printf("%s %v ip=%s ua=%q path=%s", action, reasons, ipKey, r.UserAgent(), r.URL.Path)
	ev := h.newEvent(r, ipKey, 0, "", action, reasons[0], 0)
	ev.Reasons = reasons
	h.emit(ev)
}

// isServiceWorkerScript reports a browser fetching a service worker script.
// Limited to GETs of .js paths so the header cannot exempt anything else.
func isServiceWorkerScript(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		r.Header.Get("Service-Worker") == "script" &&
		strings.HasSuffix(r.URL.Path, ".js")
}
