package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/apikeys"
)

func TestAPIKeysCreateListRevoke(t *testing.T) {
	dir := t.TempDir()
	h, srv, _, audit := versionedServer(t, filepath.Join(dir, "config.yaml"))
	store := apikeys.New(filepath.Join(dir, "api_keys.yaml"))
	srv.SetAPIKeys(store)
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := post("/api/apikeys", `{"name":"partner","cidrs":["203.0.113.0/24"],"rate":5,"burst":10}`)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created struct {
		Key  string      `json:"key"`
		Info apikeys.Key `json:"info"`
	}
	json.Unmarshal(w.Body.Bytes(), &created) //nolint:errcheck
	if !strings.HasPrefix(created.Key, apikeys.Prefix) || created.Info.ID == "" {
		t.Fatalf("create returned %+v", created)
	}

	lw := httptest.NewRecorder()
	h.ServeHTTP(lw, httptest.NewRequest("GET", "/api/apikeys", nil))
	if strings.Contains(lw.Body.String(), created.Key) || strings.Contains(lw.Body.String(), apikeys.Hash(created.Key)) {
		t.Fatal("the list shows the key or its hash")
	}
	if !strings.Contains(lw.Body.String(), `"partner"`) {
		t.Fatalf("list %s doesn't name the key", lw.Body)
	}

	if w := post("/api/apikeys", `{"name":"x","cidrs":["nope"]}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad CIDR: %d, want 422", w.Code)
	}
	if w := post("/api/apikeys/revoke", `{"id":"`+created.Info.ID+`"}`); w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w := post("/api/apikeys/revoke", `{"id":"`+created.Info.ID+`"}`); w.Code != http.StatusNotFound {
		t.Errorf("second revoke: %d, want 404", w.Code)
	}
	var actions []string
	for _, e := range audit.Recent(10, time.Time{}) {
		actions = append(actions, e.Action)
		if strings.Contains(e.Detail+e.Target, created.Key) {
			t.Error("the audit log holds the key")
		}
	}
	if got := strings.Join(actions, ","); !strings.Contains(got, "apikey_create") || !strings.Contains(got, "apikey_revoke") {
		t.Errorf("audit actions %s, want a create and a revoke", got)
	}
}
