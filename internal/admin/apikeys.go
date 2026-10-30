package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/apikeys"
)

// SetAPIKeys connects the store of Loupe-issued API keys.
func (s *Server) SetAPIKeys(k *apikeys.Store) { s.apiKeys.Store(k) }

func (s *Server) apiKeysOr503(w http.ResponseWriter) *apikeys.Store {
	k := s.apiKeys.Load()
	if k == nil {
		http.Error(w, "API keys are not available yet", http.StatusServiceUnavailable)
	}
	return k
}

// handleAPIKeysGet lists the keys: names, limits and last use, never the
// keys or their hashes.
func (s *Server) handleAPIKeysGet(w http.ResponseWriter, r *http.Request) {
	k := s.apiKeysOr503(w)
	if k == nil {
		return
	}
	writeJSON(w, map[string]any{"keys": k.List(), "path": k.Path(), "error": k.LoadErr()})
}

// handleAPIKeyCreate issues a key and returns it, the only time it is shown.
func (s *Server) handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	k := s.apiKeysOr503(w)
	if k == nil {
		return
	}
	var req struct {
		Name  string   `json:"name"`
		CIDRs []string `json:"cidrs"`
		Rate  float64  `json:"rate"`
		Burst int      `json:"burst"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	plain, key, err := k.Create(apikeys.NewKey{Name: req.Name, CIDRs: req.CIDRs, Rate: req.Rate, Burst: req.Burst})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	detail := "from anywhere"
	if len(key.CIDRs) > 0 {
		detail = "from " + strings.Join(key.CIDRs, ", ")
	}
	noteAudit(r, key.ID+" ("+key.Name+")", detail, "")
	writeJSON(w, map[string]any{"key": plain, "info": key})
}

// handleAPIKeyRevoke deletes a key; it stops working at once.
func (s *Server) handleAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	k := s.apiKeysOr503(w)
	if k == nil {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	gone, ok, err := k.Revoke(req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if !ok {
		http.Error(w, "no such key", http.StatusNotFound)
		return
	}
	noteAudit(r, gone.ID+" ("+gone.Name+")", "", "")
	writeJSON(w, map[string]any{"ok": true})
}
