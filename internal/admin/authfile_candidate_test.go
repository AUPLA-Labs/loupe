package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

// brokenAuthConfig is a config that loads (LoadBytes tolerates it so the proxy
// can start, and offers setup) but whose admin.auth_file points nowhere. It
// returns the config text and the error text a refusal must carry.
func brokenAuthConfig(t *testing.T) (cfg, wantErr string) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "nope", "admin_auth.yaml")
	cfg = cfgA + "admin:\n  listen: 0.0.0.0:9090\n  auth_file: " + missing + "\n"
	if c, err := config.LoadBytes([]byte(cfg)); err != nil || !c.Admin.NeedsSetup {
		t.Fatalf("scenario should load needing setup, got err=%v", err)
	}
	return cfg, "admin.auth_file: " + missing + " does not exist"
}

// withAdmins gives srv an admin after its routes were built, so requests in
// these tests stay unauthenticated while the console counts as set up.
func withAdmins(t *testing.T, srv *Server) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "admin_auth.yaml")
	users := []config.AdminUser{{Username: "pat", PasswordHash: testHash(t, "correct horse"), Role: config.RoleAdmin}}
	if err := config.SaveAdminAuth(file, &config.AdminAuth{Users: users}); err != nil {
		t.Fatal(err)
	}
	srv.auth = newAuth(AuthOptions{File: file, Users: users})
}

func wantRefusedWithAuthError(t *testing.T, what string, code int, body, wantErr string) {
	t.Helper()
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("%s: %d %q, want 422", what, code, body)
	}
	if got := strings.TrimSpace(body); got != wantErr {
		t.Fatalf("%s body = %q, want exactly %q", what, got, wantErr)
	}
}

func TestConfigSaveRefusesBrokenAuthFile(t *testing.T) {
	h, srv, hist, a, path := historyServer(t, cfgA)
	withAdmins(t, srv)
	bad, wantErr := brokenAuthConfig(t)

	w := postJSON(h, "/api/config", bad)
	wantRefusedWithAuthError(t, "save", w.Code, w.Body.String(), wantErr)
	if got, _ := os.ReadFile(path); string(got) != cfgA {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
	if vs, _ := hist.List("config"); len(vs) != 0 {
		t.Fatalf("%d history versions for a refused save, want none", len(vs))
	}
	if n := len(a.Recent(10, time.Time{})); n != 0 {
		t.Fatalf("%d audit entries for a refused save, want none", n)
	}
}

func TestConfigValidateRefusesBrokenAuthFile(t *testing.T) {
	h, srv, _, _, path := historyServer(t, cfgA)
	withAdmins(t, srv)
	bad, wantErr := brokenAuthConfig(t)

	w := postJSON(h, "/api/config/validate", bad)
	wantRefusedWithAuthError(t, "validate", w.Code, w.Body.String(), wantErr)
	if got, _ := os.ReadFile(path); string(got) != cfgA {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
}

func TestSettingsSaveRefusesBrokenAuthFile(t *testing.T) {
	bad, wantErr := brokenAuthConfig(t)
	h, srv, hist, a, path := historyServer(t, bad)
	withAdmins(t, srv)

	w := postJSON(h, "/api/settings", `{"values":{"abuse.rate_limit.burst":30}}`)
	wantRefusedWithAuthError(t, "settings save", w.Code, w.Body.String(), wantErr)
	if got, _ := os.ReadFile(path); string(got) != bad {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
	if vs, _ := hist.List("config"); len(vs) != 0 {
		t.Fatalf("%d history versions for a refused save, want none", len(vs))
	}
	if n := len(a.Recent(10, time.Time{})); n != 0 {
		t.Fatalf("%d audit entries for a refused save, want none", n)
	}
}

func TestRestoreRefusesBrokenAuthFile(t *testing.T) {
	h, srv, hist, a, path := historyServer(t, cfgA)
	withAdmins(t, srv)
	bad, wantErr := brokenAuthConfig(t)
	id, err := hist.Save("config", []byte(bad))
	if err != nil {
		t.Fatal(err)
	}

	w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+id+`"}`)
	wantRefusedWithAuthError(t, "restore", w.Code, w.Body.String(), wantErr)
	if got, _ := os.ReadFile(path); string(got) != cfgA {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
	if n := len(a.Recent(10, time.Time{})); n != 0 {
		t.Fatalf("%d audit entries for a refused restore, want none", n)
	}
}

// A console nobody has set up yet saves a config whose users file doesn't
// exist: that is every new install until the setup link is used.
func TestConfigSaveBeforeSetup(t *testing.T) {
	h, _, _, _, _ := historyServer(t, cfgA)
	bad, _ := brokenAuthConfig(t)
	if w := postJSON(h, "/api/config/validate", bad); w.Code != http.StatusNoContent {
		t.Errorf("validate before setup = %d %s, want 204", w.Code, w.Body)
	}
}
