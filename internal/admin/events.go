package admin

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Time    time.Time `json:"t"`
	VID     string    `json:"vid,omitempty"` // verdict ID of the request that produced this event
	Action  string    `json:"action"`        // ALLOW, BLOCK, CHALLENGE, PASS, FAIL, LIMIT
	IP      string    `json:"ip"`
	ASN     uint      `json:"asn,omitempty"`
	Org     string    `json:"org,omitempty"`
	Method  string    `json:"method,omitempty"`
	Host    string    `json:"host,omitempty"`
	Path    string    `json:"path,omitempty"`
	UA      string    `json:"ua,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Score   int       `json:"score,omitempty"`
	Reasons []string  `json:"reasons,omitempty"` // individual signal names that contributed to Score

	// The network as the AUPLA database and the overlay's published lists
	// saw the client: where the address is used, the network's type, the
	// address's classes (tor_exit, vpn, relay, ...) and the list's provider.
	Country    string   `json:"country,omitempty"`
	NetType    string   `json:"net_type,omitempty"`
	Classes    []string `json:"classes,omitempty"`
	Provider   string   `json:"provider,omitempty"`
	Datacenter bool     `json:"dc,omitempty"`

	Bot       string `json:"bot,omitempty"`        // known bot the User-Agent claims (bots catalog ID)
	BotStatus string `json:"bot_status,omitempty"` // verified, spoofed, unverifiable or claimed

	// BadIP is how many public blacklists named the client's address when
	// the event was recorded (the bad-IP feed), 0 if none or disabled.
	BadIP int `json:"bad_ip,omitempty"`

	// Rule is the rules.yaml rule that was enforced for this request (it
	// allowed, blocked or raised the challenge tier). LoggedRules are the
	// IDs of log-only rules that also matched, in file order.
	Rule        string   `json:"rule,omitempty"`
	LoggedRules []string `json:"logged_rules,omitempty"`

	Pressure  float64 `json:"pressure,omitempty"`   // current decayed IP pressure at dispatch time
	TierFloor int     `json:"tier_floor,omitempty"` // reputation-derived tier floor, as int(tier.Tier)
	Tier      int     `json:"tier,omitempty"`       // final effective tier chosen, as int(tier.Tier)

	// Lumen is the Lumen level the client's challenge was scored at, as
	// int(lumen.Level) — in shadow mode the level it would have been
	// served. LumenRate is the server-measured hash rate of its answer
	// (hashes/s, issue to answer) and LumenSpaceMs the client-reported
	// proof-of-space time.
	// LumenDispatch marks the event of the navigation that was sent to a
	// challenge (Lumen is then the level it will be scored at), as opposed
	// to the events of its answer.
	Lumen         *int    `json:"lumen,omitempty"`
	LumenDispatch bool    `json:"lumen_dispatch,omitempty"`
	LumenRate     float64 `json:"lumen_rate,omitempty"`
	LumenSpaceMs  float64 `json:"lumen_space_ms,omitempty"`

	// FP holds per-surface fingerprint component hashes (canvas, webgl,
	// fonts, ...) from a pulse or verify answer. Raw fingerprint values are
	// never stored.
	FP map[string]string `json:"fp,omitempty"`

	// Count is set on a summary event: one event standing for Count
	// repetitive requests (a cleared visitor's assets and API calls, a
	// rate-limited burst) from the same client, between Since and Until.
	// Paths holds the busiest of their paths. Ordinary events leave these
	// unset and stand for one request; see N.
	Count int         `json:"count,omitempty"`
	Since time.Time   `json:"since,omitzero"`
	Until time.Time   `json:"until,omitzero"`
	Paths []PathCount `json:"paths,omitempty"`
}

// PathCount is how many of a summary event's requests went to Path.
type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// N is how many requests e stands for: Count for a summary event, else 1.
func (e *Event) N() int {
	if e.Count > 0 {
		return e.Count
	}
	return 1
}

type Store struct {
	mu sync.RWMutex
	// buf is a ring of the stored events, oldest at start. It grows on
	// demand up to limit, and once full each new event replaces the oldest.
	buf    []Event
	start  int
	size   int
	limit  int
	maxAge time.Duration // events older than this are deleted; 0 = keep by count only
	subsMu sync.Mutex
	subs   map[chan Event]struct{}
	// logMu guards logFile, which prune swaps for a rewritten file, and
	// logLines, the number of events in it.
	logMu    sync.Mutex
	logPath  string
	logFile  *os.File
	logLines int
	pruneLog bool // apply the limit to the log file as well
	orgOf    atomic.Pointer[func(asn uint) string]
	stop     chan struct{}
}

// agedCeiling bounds an age-limited store's memory: under a flood the
// newest events are kept and the oldest dropped early, as with a count limit.
var agedCeiling = 200_000

// pruneInterval is how often a store applies its limit to what it keeps
// beyond the ring: expired events in memory, and the log file. Between
// prunes a count-limited log can run over by an interval's events.
const pruneInterval = time.Hour

// SetOrgLookup gives Add a way to name events that arrive without an AS
// name, such as summaries put together before the name was looked up.
func (s *Store) SetOrgLookup(fn func(asn uint) string) { s.orgOf.Store(&fn) }

type StoreOptions struct {
	Capacity int           // newest events kept, when MaxAge is 0; default 5000
	MaxAge   time.Duration // delete events older than this instead
	LogPath  string        // JSONL event log; empty = in-memory only
	PruneLog bool          // apply the limit to LogPath too, not just memory
}

// NewStore keeps the newest capacity events in memory. The log file, if
// any, keeps every event.
func NewStore(capacity int, logPath string) (*Store, error) {
	return OpenStore(StoreOptions{Capacity: capacity, LogPath: logPath})
}

// OpenStore opens a store limited by count or, with MaxAge, by age. The
// limit is applied on opening and then every pruneInterval.
func OpenStore(o StoreOptions) (*Store, error) {
	limit := o.Capacity
	if o.MaxAge > 0 {
		limit = agedCeiling
	} else if limit <= 0 {
		limit = 5000
	}
	s := &Store{limit: limit, maxAge: o.MaxAge, logPath: o.LogPath, pruneLog: o.PruneLog && o.LogPath != "", subs: make(map[chan Event]struct{})}
	if o.MaxAge == 0 {
		s.buf = make([]Event, limit)
	}
	if o.LogPath != "" {
		if err := s.openLog(); err != nil {
			return nil, err
		}
	}
	if o.MaxAge == 0 && !s.pruneLog {
		return s, nil // nothing grows past its limit
	}
	s.stop = make(chan struct{})
	go func() {
		t := time.NewTicker(pruneInterval)
		defer t.Stop()
		for {
			select {
			case now := <-t.C:
				s.prune(now)
			case <-s.stop:
				return
			}
		}
	}()
	return s, nil
}

// openLog prunes the log file if asked to, loads it and opens it for
// appending.
func (s *Store) openLog() error {
	if s.pruneLog {
		var cutoff time.Time
		if s.maxAge > 0 {
			cutoff = time.Now().Add(-s.maxAge)
		}
		if err := s.rewriteLog(cutoff); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := s.loadFile(s.logPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	s.logFile = f
	return nil
}

func (s *Store) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var cutoff time.Time
	if s.maxAge > 0 {
		cutoff = time.Now().Add(-s.maxAge)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.Before(cutoff) {
			renameLegacyReasons(&e)
			s.push(e)
		}
	}
	return sc.Err()
}

// push stores e, growing the ring while it is below limit and otherwise
// overwriting the oldest event. Callers must hold s.mu for writing.
func (s *Store) push(e Event) {
	if s.size == len(s.buf) && len(s.buf) < s.limit {
		s.resize(min(max(2*len(s.buf), 1024), s.limit))
	}
	if s.size < len(s.buf) {
		s.buf[(s.start+s.size)%len(s.buf)] = e
		s.size++
		return
	}
	s.buf[s.start] = e
	s.start = (s.start + 1) % len(s.buf)
}

// resize moves the stored events into a ring of n slots (n >= s.size).
func (s *Store) resize(n int) {
	buf := make([]Event, n)
	for i := 0; i < s.size; i++ {
		buf[i] = s.buf[(s.start+i)%len(s.buf)]
	}
	s.buf, s.start = buf, 0
}

// prune applies the store's limit at now: it deletes the events older than
// maxAge from memory, and, with pruneLog, trims the log file to match.
func (s *Store) prune(now time.Time) {
	if s.pruneLog {
		defer s.pruneLogFile(now)
	}
	if s.maxAge == 0 {
		return // the ring holds the count limit by itself
	}
	// Events are only roughly in time order (a summary is logged when it
	// closes), so every one is checked.
	cutoff := now.Add(-s.maxAge)
	s.mu.Lock()
	kept := 0
	for i := 0; i < s.size; i++ {
		e := s.buf[(s.start+i)%len(s.buf)]
		if !e.Time.Before(cutoff) {
			s.buf[(s.start+kept)%len(s.buf)] = e
			kept++
		}
	}
	for i := kept; i < s.size; i++ {
		s.buf[(s.start+i)%len(s.buf)] = Event{}
	}
	s.size = kept
	// Hand memory back after a flood has expired.
	if len(s.buf) > 1024 && s.size < len(s.buf)/4 {
		s.resize(max(2*s.size, 1024))
	}
	s.mu.Unlock()
}

func (s *Store) pruneLogFile(now time.Time) {
	var cutoff time.Time
	if s.maxAge > 0 {
		cutoff = now.Add(-s.maxAge)
	} else {
		s.logMu.Lock()
		over := s.logLines > s.limit
		s.logMu.Unlock()
		if !over {
			return
		}
	}
	if err := s.rewriteLog(cutoff); err != nil {
		log.Printf("admin: pruning %s: %v", s.logPath, err)
	}
}

// rewriteLog removes from the log file the events logged before cutoff,
// lines that aren't events and, for a count limit, all but the newest
// s.limit events. The file is replaced atomically, and left untouched when
// nothing is removed.
func (s *Store) rewriteLog(cutoff time.Time) error {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	skip := 0
	if s.maxAge == 0 {
		n, err := countLogEvents(s.logPath)
		if err != nil {
			return err
		}
		skip = max(n-s.limit, 0)
	}
	in, err := os.Open(s.logPath)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.logPath), filepath.Base(s.logPath)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	out := bufio.NewWriter(tmp)
	dropped, kept := 0, 0
	r := bufio.NewReader(in)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if t, ok := logLineTime(line); !ok || t.Before(cutoff) {
				dropped++
			} else if skip > 0 {
				skip--
				dropped++
			} else {
				kept++
				out.Write(line)
				if line[len(line)-1] != '\n' {
					out.WriteByte('\n')
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			tmp.Close()
			return err
		}
	}
	s.logLines = kept
	if dropped == 0 {
		tmp.Close()
		return nil
	}
	if err := out.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.logPath); err != nil {
		return err
	}
	if s.logFile != nil {
		f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		s.logFile.Close()
		s.logFile = f
	}
	log.Printf("admin: removed %d old or unreadable lines from %s", dropped, s.logPath)
	return nil
}

// logLineTime returns the time of the event on a log line, if it is one.
func logLineTime(line []byte) (time.Time, bool) {
	var e struct {
		Time time.Time `json:"t"`
	}
	return e.Time, json.Unmarshal(line, &e) == nil
}

// countLogEvents counts the lines of the log file that are events.
func countLogEvents(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if _, ok := logLineTime(line); len(line) > 0 && ok {
			n++
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// legacyReasons maps reason IDs that events were logged with before Lumen
// replaced the old proof-of-work onto their current IDs, so the dashboard
// shows one name for each. The log file itself is left as written.
var legacyReasons = map[string]string{
	"request_score_altcha": "request_score_lumen",
	"altcha":               "pow_invalid",
}

func renameLegacyReasons(e *Event) {
	if id, ok := legacyReasons[e.Reason]; ok {
		e.Reason = id
	}
	for i, r := range e.Reasons {
		if id, ok := legacyReasons[r]; ok {
			e.Reasons[i] = id
		}
	}
}

func (s *Store) Add(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if fn := s.orgOf.Load(); fn != nil && e.ASN != 0 && e.Org == "" {
		e.Org = (*fn)(e.ASN)
	}
	s.mu.Lock()
	s.push(e)
	s.mu.Unlock()

	s.logMu.Lock()
	if s.logFile != nil {
		b, _ := json.Marshal(e)
		s.logFile.Write(append(b, '\n'))
		s.logLines++
	}
	s.logMu.Unlock()

	s.subsMu.Lock()
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
	s.subsMu.Unlock()
}

// at returns the i-th stored event, oldest first. Callers must hold s.mu.
func (s *Store) at(i int) *Event { return &s.buf[(s.start+i)%len(s.buf)] }

// Recent returns the last n events (oldest-first), optionally filtered by action.
// n <= 0 returns all stored events.
func (s *Store) Recent(n int, action string) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Event, 0, s.size)
	for i := 0; i < s.size; i++ {
		if e := s.at(i); action == "" || e.Action == action {
			result = append(result, *e)
		}
	}
	if n > 0 && len(result) > n {
		result = result[len(result)-n:]
	}
	return result
}

// eachNewest calls fn for every stored event, newest first, until fn
// returns false. Callers must hold s.mu (read or write).
func (s *Store) eachNewestLocked(fn func(e *Event) bool) {
	for i := s.size - 1; i >= 0; i-- {
		if !fn(s.at(i)) {
			return
		}
	}
}

// BufferInfo describes how much history the in-memory ring buffer holds,
// so the dashboard can say honestly what a time window is drawn from.
// MaxAge (seconds) is set when events are deleted by age rather than count;
// Capacity is then only the memory ceiling.
type BufferInfo struct {
	Size     int       `json:"size"`
	Capacity int       `json:"capacity"`
	MaxAge   float64   `json:"max_age,omitempty"`
	Oldest   time.Time `json:"oldest,omitempty"`
	Newest   time.Time `json:"newest,omitempty"`
}

func (s *Store) Buffer() BufferInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bufferLocked()
}

func (s *Store) bufferLocked() BufferInfo {
	bi := BufferInfo{Size: s.size, Capacity: s.limit, MaxAge: s.maxAge.Seconds()}
	if s.size > 0 {
		bi.Oldest = s.at(0).Time
		bi.Newest = s.at(s.size - 1).Time
	}
	return bi
}

// Subscribers reports the number of live-stream clients.
func (s *Store) Subscribers() int {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	return len(s.subs)
}

func (s *Store) Subscribe() chan Event {
	ch := make(chan Event, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan Event) {
	s.subsMu.Lock()
	delete(s.subs, ch)
	s.subsMu.Unlock()
}

func (s *Store) Close() {
	if s.stop != nil {
		close(s.stop)
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if s.logFile != nil {
		s.logFile.Close()
	}
}
