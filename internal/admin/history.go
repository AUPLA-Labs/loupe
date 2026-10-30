package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/AUPLA-Labs/loupe/internal/bots"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/rules"
)

// historyFile resolves the file query parameter to the history name and the
// path of the file on disk. Bot policy needs the manager, so it can reply 503.
func (s *Server) historyFile(w http.ResponseWriter, file string) (name, path string, ok bool) {
	switch file {
	case "config":
		return file, s.cfgPath, true
	case "bots":
		m := s.botsOr503(w)
		if m == nil {
			return "", "", false
		}
		return file, m.PolicyFile(), true
	case "rules":
		m := s.rulesOr503(w)
		if m == nil {
			return "", "", false
		}
		return file, m.Path(), true
	}
	http.Error(w, `file must be "config", "bots" or "rules"`, http.StatusBadRequest)
	return "", "", false
}

// historyBytes fetches one saved version, replying 400 for a malformed id and
// 404 for one that was never saved (or has been pruned).
func (s *Server) historyBytes(w http.ResponseWriter, name, id string) ([]byte, bool) {
	h := s.history.Load()
	if h == nil {
		http.Error(w, "version history is not enabled", http.StatusNotFound)
		return nil, false
	}
	data, err := h.Get(name, id)
	var pathErr *fs.PathError
	switch {
	case err == nil:
		return data, true
	case errors.Is(err, fs.ErrNotExist):
		http.Error(w, "no such version "+id, http.StatusNotFound)
	case errors.As(err, &pathErr):
		http.Error(w, "read version: "+err.Error(), http.StatusInternalServerError)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	return nil, false
}

// readCurrent reads the file as it is on disk; one that doesn't exist yet
// reads as empty.
func readCurrent(w http.ResponseWriter, path string) ([]byte, bool) {
	if path == "" {
		return nil, true
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		http.Error(w, "read file: "+err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	return data, true
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	name, path, ok := s.historyFile(w, r.URL.Query().Get("file"))
	if !ok {
		return
	}
	h := s.history.Load()
	versions, err := h.List(name)
	if err != nil {
		http.Error(w, "list versions: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk, ok := readCurrent(w, path)
	if !ok {
		return
	}
	// The newest version whose bytes are the file's: a hand edit since the
	// last save leaves none.
	current := ""
	if len(disk) > 0 {
		for _, v := range versions {
			if v.Size != len(disk) {
				continue
			}
			if got, err := h.Get(name, v.ID); err == nil && bytes.Equal(got, disk) {
				current = v.ID
				break
			}
		}
	}
	if versions == nil {
		versions = []config.Version{}
	}
	writeJSON(w, map[string]any{"versions": versions, "current": current})
}

func (s *Server) handleHistoryDiff(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name, path, ok := s.historyFile(w, q.Get("file"))
	if !ok {
		return
	}
	// Either end may be "current": the file as it is on disk.
	side := func(id string) ([]byte, bool) {
		if id == "current" {
			return readCurrent(w, path)
		}
		return s.historyBytes(w, name, id)
	}
	from, ok := side(q.Get("from"))
	if !ok {
		return
	}
	to, ok := side(q.Get("to"))
	if !ok {
		return
	}
	lines := config.LineDiff(from, to)
	if lines == nil {
		lines = []config.DiffLine{}
	}
	added, removed := config.DiffStat(lines)
	writeJSON(w, map[string]any{"lines": lines, "added": added, "removed": removed})
}

func (s *Server) handleHistoryRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File    string `json:"file"`
		Version string `json:"version"`
		ETag    string `json:"etag"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	name, path, ok := s.historyFile(w, req.File)
	if !ok {
		return
	}
	data, ok := s.historyBytes(w, name, req.Version)
	if !ok {
		return
	}
	switch name {
	case "bots":
		s.restoreBots(w, r, data, req.Version)
		return
	case "rules":
		s.restoreRules(w, r, data, req.Version)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	current, ok := readCurrent(w, path)
	if !ok {
		return
	}
	if req.ETag != "" && req.ETag != configETag(current) {
		http.Error(w, "config.yaml changed on disk since it was loaded — reload and try again", http.StatusPreconditionFailed)
		return
	}
	// A saved version passed these checks once, but the validation rules or a
	// hand edit of the history directory may have changed since.
	cfg, err := s.validateCandidate(data)
	if err == nil {
		err = checkOrdering(cfg)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if !s.keepCurrent(w, "config", current) {
		return
	}
	if err := writeFileAtomic(path, data, 0600); err != nil {
		http.Error(w, "write config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	version := s.saveVersion("config", data)
	noteAudit(r, "config.yaml", "restored "+req.Version, version)
	log.Printf("admin: config restored to version %s", req.Version)
	w.Header().Set("ETag", configETag(data))
	writeJSON(w, map[string]any{"etag": configETag(data), "version": version, "restart": true})
}

// keepCurrent records the bytes about to be replaced as a version, so a
// restore never discards an edit made outside the dashboard. A save that
// already matches the newest version costs nothing. When it fails the restore
// is refused: better no restore than a lost file.
func (s *Server) keepCurrent(w http.ResponseWriter, name string, current []byte) bool {
	if len(current) == 0 {
		return true
	}
	if _, err := s.history.Load().Save(name, current); err != nil {
		log.Printf("admin: keep current %s before restore: %v", name, err)
		http.Error(w, "couldn't save the current "+name+" to the history, so nothing was restored: "+err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

// restoreBots applies a saved policy through the manager, which validates it,
// writes the file, applies it live and records the new version.
func (s *Server) restoreBots(w http.ResponseWriter, r *http.Request, data []byte, restored string) {
	m := s.botsOr503(w)
	if m == nil {
		return
	}
	p, err := bots.ParsePolicy(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	current, ok := readCurrent(w, m.PolicyFile())
	if !ok || !s.keepCurrent(w, "bots", current) {
		return
	}
	if _, err := m.Save(p); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	after, _ := os.ReadFile(m.PolicyFile())
	version := s.botsVersion(after)
	noteAudit(r, "bots.yaml", "restored "+restored, version)
	log.Printf("admin: bot policy restored to version %s", restored)
	writeJSON(w, map[string]string{"version": version})
}

// restoreRules applies a saved rules.yaml through the manager, which validates
// it, writes the file and applies it at once. The file it replaces is kept as
// a version first.
func (s *Server) restoreRules(w http.ResponseWriter, r *http.Request, data []byte, restored string) {
	m := s.rulesOr503(w)
	if m == nil {
		return
	}
	rs, err := rules.Parse(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	version, after, err := s.saveRules(r, m, rs, "", "restored "+restored)
	if err != nil {
		writeRulesError(w, err)
		return
	}
	log.Printf("admin: rules restored to version %s", restored)
	writeJSON(w, map[string]string{"etag": configETag(after), "version": version})
}
