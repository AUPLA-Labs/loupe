package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/underattack"
)

func TestUnderAttackEndpoint(t *testing.T) {
	dir := t.TempDir()
	h, srv, _, audit := versionedServer(t, filepath.Join(dir, "config.yaml"))
	srv.SetUnderAttack(underattack.New(filepath.Join(dir, "under_attack.json")))
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/under-attack", strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"enabled":true,"duration":"2h"}`); w.Code != http.StatusBadRequest {
		t.Errorf("unknown duration: %d, want 400", w.Code)
	}
	if w := post(`{"enabled":true,"duration":"6h","min_tier":"magic"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unknown tier: %d, want 422", w.Code)
	}
	if w := post(`{"enabled":true,"duration":"6h","min_tier":"prism","revoke_clearance":true}`); w.Code != 200 {
		t.Fatalf("turn on: %d %s", w.Code, w.Body)
	}
	g := httptest.NewRecorder()
	h.ServeHTTP(g, httptest.NewRequest("GET", "/api/under-attack", nil))
	var st underattack.State
	json.Unmarshal(g.Body.Bytes(), &st) //nolint:errcheck
	if !st.Enabled || st.MinTier != "prism" || !st.RevokeClearance || st.Until == nil {
		t.Fatalf("state %+v", st)
	}
	es := audit.Recent(5, time.Time{})
	if len(es) == 0 || es[0].Action != "under_attack" || !strings.Contains(es[0].Detail, "prism") {
		t.Fatalf("audit %+v, want an under_attack entry", es)
	}
}
