package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/aupldb"
	"github.com/AUPLA-Labs/loupe/internal/version"
)

// ASNSource is the network database: the System page reports it, the AUPLA
// terms are shown and accepted through it, and investigations read what it
// knows about an address or a network.
type ASNSource interface {
	Status() aupldb.Status
	OverlayStatus() []aupldb.ListStatus
	Lookup(ip net.IP) (asn.Record, error)
	Info(asn uint) asn.ASNInfo
	Terms(ctx context.Context) (asn.Terms, error)
	Accept(ctx context.Context, version, software string) error
	CachedName(asn uint) string
	IsDatacenter(asn uint) bool
	IsBlocked(asn uint) bool
	IsAllowed(asn uint) bool
}

// SetASN connects the network database.
func (s *Server) SetASN(src ASNSource) { s.asn.Store(&src) }

func (s *Server) asnSource() ASNSource {
	if p := s.asn.Load(); p != nil {
		return *p
	}
	return nil
}

// handleNetworkTerms returns AUPLA's current terms, fetched by Loupe so the
// browser never talks to the API itself.
func (s *Server) handleNetworkTerms(w http.ResponseWriter, r *http.Request) {
	src := s.asnSource()
	if src == nil {
		http.Error(w, "network database not connected", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	t, err := src.Terms(ctx)
	if err != nil {
		log.Printf("asn: fetch terms: %v", err)
		http.Error(w, "Couldn't load the terms from AUPLA: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, t)
}

// handleNetworkAccept registers this install with AUPLA under the terms
// version the admin was shown.
func (s *Server) handleNetworkAccept(w http.ResponseWriter, r *http.Request) {
	src := s.asnSource()
	if src == nil {
		http.Error(w, "network database not connected", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.Version == "" {
		http.Error(w, `body must be {"version": "<terms version>"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := src.Accept(ctx, req.Version, loupeSoftware()); err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, asn.ErrTermsChanged) {
			status = http.StatusConflict
		}
		log.Printf("asn: accept terms: %v", err)
		http.Error(w, err.Error(), status)
		return
	}
	noteAudit(r, "aupla_terms", req.Version, "")
	writeJSON(w, src.Status())
}

// loupeSoftware identifies this build to AUPLA, e.g. "loupe/de39f82abc12".
func loupeSoftware() string {
	v := "dev"
	if version.Version != "" {
		return "loupe/" + version.Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
		for _, st := range bi.Settings {
			if st.Key == "vcs.revision" && len(st.Value) >= 12 {
				v = st.Value[:12]
			}
		}
	}
	return "loupe/" + v
}
