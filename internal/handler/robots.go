package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/bots"
)

// Managed robots.txt (bots policy robots.mode): Loupe serves /robots.txt
// itself, with a section generated from the bot policy — every blocked bot
// disallowed, plus optional content signals — so what crawlers are told
// always matches what Loupe enforces. In merge mode the site's own
// robots.txt, fetched from the backend per host, follows that section.

const (
	robotsCacheTTL   = 5 * time.Minute
	robotsMaxBytes   = 512 << 10
	robotsFetchLimit = 5 * time.Second
)

// originRobots is a host's own robots.txt as the backend serves it.
type originRobots struct {
	status  int // 200, or the status that means "no file" (4xx)
	body    string
	fetched time.Time
}

type robotsCache struct {
	backend *url.URL
	client  *http.Client
	mu      sync.Mutex
	hosts   map[string]originRobots
}

func newRobotsCache(backend *url.URL) *robotsCache {
	return &robotsCache{
		backend: backend,
		client: &http.Client{
			Timeout: robotsFetchLimit,
			// A redirect is the backend's answer, not something to chase
			// through a different host behind Loupe's back.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		hosts: make(map[string]originRobots),
	}
}

var errOriginUnavailable = errors.New("site's robots.txt unavailable")

// get returns host's own robots.txt as served over scheme: from cache when
// fresh, else from the backend. A 4xx means the site has none (status recorded, empty body). A
// 5xx, timeout or redirect returns errOriginUnavailable together with the
// last good copy, if any.
func (c *robotsCache) get(ctx context.Context, scheme, host string) (originRobots, error) {
	host = strings.ToLower(host)
	key := scheme + "://" + host
	c.mu.Lock()
	cached, ok := c.hosts[key]
	c.mu.Unlock()
	if ok && time.Since(cached.fetched) < robotsCacheTTL {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.backend.String()+"/robots.txt", nil)
	if err != nil {
		return cached, err
	}
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", scheme)
	req.Header.Set("User-Agent", "Loupe (managed robots.txt)")
	resp, err := c.client.Do(req)
	if err != nil {
		return cached, fmt.Errorf("%w: %v", errOriginUnavailable, err)
	}
	defer resp.Body.Close()

	var o originRobots
	switch {
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, robotsMaxBytes))
		if err != nil {
			return cached, fmt.Errorf("%w: %v", errOriginUnavailable, err)
		}
		o = originRobots{status: http.StatusOK, body: string(body)}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		o = originRobots{status: resp.StatusCode}
	default:
		return cached, fmt.Errorf("%w: HTTP %d", errOriginUnavailable, resp.StatusCode)
	}
	o.fetched = time.Now()
	c.mu.Lock()
	c.hosts[key] = o
	c.mu.Unlock()
	return o, nil
}

// RobotsPreview is what https://host/robots.txt would serve right now, for
// the dashboard. note explains where it came from.
func (h *Handler) RobotsPreview(ctx context.Context, host string) (body, note string, err error) {
	if h.bots == nil {
		return "", "", errors.New("bot policy not loaded")
	}
	section := h.bots.RobotsSection()
	switch h.bots.RobotsMode() {
	case bots.RobotsReplace:
		return bots.ReplaceRobots(section), "Loupe's file only; the site's own robots.txt is ignored.", nil
	case bots.RobotsMerge:
		o, err := h.robots.get(ctx, "https", host)
		switch {
		case err != nil && o.fetched.IsZero():
			return "", "", err
		case err != nil:
			return bots.MergeRobots(section, o.body), "The site's robots.txt couldn't be fetched just now; showing it with the last good copy.", nil
		case o.status != http.StatusOK:
			return section, fmt.Sprintf("The site has no robots.txt of its own (HTTP %d), so Loupe's section is the whole file.", o.status), nil
		}
		return bots.MergeRobots(section, o.body), "Loupe's section, followed by the site's own robots.txt.", nil
	default:
		o, err := h.robots.get(ctx, "https", host)
		if err != nil {
			return "", "", err
		}
		if o.status != http.StatusOK {
			return "", fmt.Sprintf("Managed robots.txt is off and the site has none (HTTP %d).", o.status), nil
		}
		return o.body, "Managed robots.txt is off; the site's own file is served unchanged.", nil
	}
}

// serveRobots answers /robots.txt when robots.txt is managed. It returns
// false when it isn't, so the request is proxied as before.
func (h *Handler) serveRobots(w http.ResponseWriter, r *http.Request) bool {
	if h.bots == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	section := h.bots.RobotsSection()
	var body string
	switch h.bots.RobotsMode() {
	case bots.RobotsReplace:
		body = bots.ReplaceRobots(section)
	case bots.RobotsMerge:
		o, err := h.robots.get(r.Context(), requestScheme(r), r.Host)
		switch {
		case err != nil && o.fetched.IsZero():
			// Crawlers read a 5xx robots.txt as "come back later", which is
			// the honest answer while the site can't say what its rules are.
			log.Printf("robots.txt %s: %v", r.Host, err)
			w.Header().Set("Retry-After", "300")
			http.Error(w, "robots.txt temporarily unavailable", http.StatusServiceUnavailable)
			return true
		case o.status == http.StatusOK:
			body = bots.MergeRobots(section, o.body)
		default:
			body = section
		}
	default:
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Robots-Managed-By", "Loupe")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		return true
	}
	io.WriteString(w, body)
	return true
}
