package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/underattack"
)

// SetUnderAttack connects the under-attack switch.
func (s *Server) SetUnderAttack(u *underattack.Switch) { s.underAttack.Store(u) }

var underAttackDurations = map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "": 0}

func (s *Server) underAttackOr503(w http.ResponseWriter) *underattack.Switch {
	u := s.underAttack.Load()
	if u == nil {
		http.Error(w, "the under-attack switch is not available yet", http.StatusServiceUnavailable)
	}
	return u
}

func (s *Server) handleUnderAttackGet(w http.ResponseWriter, r *http.Request) {
	if u := s.underAttackOr503(w); u != nil {
		writeJSON(w, u.State())
	}
}

// handleUnderAttackSet turns the switch on or off. Duration "" keeps it on
// until it is turned off.
func (s *Server) handleUnderAttackSet(w http.ResponseWriter, r *http.Request) {
	u := s.underAttackOr503(w)
	if u == nil {
		return
	}
	var req struct {
		Enabled         bool   `json:"enabled"`
		Duration        string `json:"duration"`
		MinTier         string `json:"min_tier"`
		RevokeClearance bool   `json:"revoke_clearance"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	d, ok := underAttackDurations[req.Duration]
	if !ok {
		http.Error(w, `duration must be "1h", "6h", "24h" or "" (until turned off)`, http.StatusBadRequest)
		return
	}
	by := ""
	if usr, ok := requestUser(r); ok {
		by = usr.Username
	}
	st, err := u.Set(req.Enabled, d, req.MinTier, req.RevokeClearance, by)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	detail := "off"
	if st.Enabled {
		detail = "on, minimum " + st.MinTier
		if st.Until != nil {
			detail += ", until " + st.Until.Format(time.RFC3339)
		} else {
			detail += ", until turned off"
		}
		if st.RevokeClearance {
			detail += ", earlier clearances revoked"
		}
	}
	noteAudit(r, "under attack", detail, "")
	writeJSON(w, st)
}
