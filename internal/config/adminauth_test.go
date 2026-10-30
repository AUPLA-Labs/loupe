package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const totpTestSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // 20 bytes

func TestLegacySingleUserAuthLoads(t *testing.T) {
	a, err := ParseAdminAuth([]byte("username: \"pat\"\npassword_hash: \"$2a$10$abc\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []AdminUser{{Username: "pat", PasswordHash: "$2a$10$abc", Role: RoleAdmin}}
	if !reflect.DeepEqual(a.Users, want) {
		t.Errorf("Users = %+v, want %+v", a.Users, want)
	}
	if a.Username != "" || a.PasswordHash != "" {
		t.Errorf("legacy fields should be cleared after folding, got %q / %q", a.Username, a.PasswordHash)
	}
}

func TestAdminAuthValidate(t *testing.T) {
	admin := AdminUser{Username: "pat", PasswordHash: "$2a$10$abc", Role: RoleAdmin}
	viewer := AdminUser{Username: "sam", PasswordHash: "$2a$10$def", Role: RoleViewer}
	with := func(u AdminUser, f func(*AdminUser)) AdminUser { f(&u); return u }

	tests := []struct {
		name  string
		users []AdminUser
		want  string // empty = valid
	}{
		{"admin and viewer", []AdminUser{admin, viewer}, ""},
		{"no users", nil, "no users"},
		{"bad username chars", []AdminUser{with(admin, func(u *AdminUser) { u.Username = "pa ula" })}, `invalid username "pa ula"`},
		{"empty username", []AdminUser{with(admin, func(u *AdminUser) { u.Username = "" })}, `invalid username ""`},
		{"username too long", []AdminUser{with(admin, func(u *AdminUser) { u.Username = strings.Repeat("a", 65) })}, "invalid username"},
		{"duplicate ignoring case", []AdminUser{admin, with(viewer, func(u *AdminUser) { u.Username = "PAT" })}, `duplicate username "PAT"`},
		{"hash not bcrypt", []AdminUser{with(admin, func(u *AdminUser) { u.PasswordHash = "plain" })}, `user "pat" has no valid password_hash`},
		{"unknown role", []AdminUser{admin, with(viewer, func(u *AdminUser) { u.Role = "root" })}, `user "sam" has unknown role "root"`},
		{"no admin", []AdminUser{viewer}, "at least one admin must remain"},
		{"totp secret not base32", []AdminUser{with(admin, func(u *AdminUser) { u.TOTPSecret = "not base32!" })}, `user "pat" has an invalid totp_secret`},
		{"totp secret too short", []AdminUser{with(admin, func(u *AdminUser) { u.TOTPSecret = "JBSWY3DPEHPK3PXP" })}, `user "pat" has an invalid totp_secret`},
		{"totp secret lower case", []AdminUser{with(admin, func(u *AdminUser) { u.TOTPSecret = strings.ToLower(totpTestSecret) })}, ""},
		{"bad recovery hash", []AdminUser{with(admin, func(u *AdminUser) { u.RecoveryHashes = []string{"$2a$10$ok", "nope"} })}, `user "pat" has an invalid recovery hash`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&AdminAuth{Users: tt.users}).Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestParseAdminAuthLegacyErrors(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"only username", "username: pat\n", "admin auth file must set both username and password_hash"},
		{"only hash", "password_hash: \"$2a$10$abc\"\n", "admin auth file must set both username and password_hash"},
		{"mixed", "username: pat\npassword_hash: \"$2a$10$abc\"\nusers:\n  - username: sam\n    password_hash: \"$2a$10$d\"\n    role: admin\n",
			"admin auth file mixes the old username/password_hash keys with users:"},
		{"empty file", "", "no users"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAdminAuth([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestSaveAdminAuthRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	in := &AdminAuth{Users: []AdminUser{
		{Username: "pat", PasswordHash: "$2a$10$abc", Role: RoleAdmin, TOTPSecret: totpTestSecret, TOTPLastStep: 12345, RecoveryHashes: []string{"$2a$10$r1", "$2a$10$r2"}},
		{Username: "sam", PasswordHash: "$2a$10$def", Role: RoleViewer, TOTPSecret: totpTestSecret},
	}}
	if err := SaveAdminAuth(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAdminAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("round trip changed the file:\n got %+v\nwant %+v", got, in)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), "# Managed by Loupe (dashboard and loupe -setup-admin). Hand edits are picked up within a second.\n") {
		t.Errorf("missing header comment:\n%s", raw)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "username:") || strings.HasPrefix(line, "password_hash:") {
			t.Errorf("top-level legacy key written: %q", line)
		}
	}
}

func TestSaveAdminAuthRefusesInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	err := SaveAdminAuth(path, &AdminAuth{Users: []AdminUser{{Username: "sam", PasswordHash: "$2a$10$def", Role: RoleViewer}}})
	if err == nil || !strings.Contains(err.Error(), "at least one admin must remain") {
		t.Fatalf("error = %v, want at least one admin must remain", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("file should not exist after a refused save, stat err = %v", statErr)
	}
}

func TestLoadBytesFillsAdminUsers(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "admin_auth.yaml")
	if err := os.WriteFile(authPath, []byte("username: pat\npassword_hash: \"$2a$10$abc\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadBytes([]byte("admin:\n  auth_file: " + authPath + "\n  require_2fa: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Admin.Users) != 1 || cfg.Admin.Users[0].Username != "pat" || cfg.Admin.Users[0].Role != RoleAdmin {
		t.Errorf("Admin.Users = %+v, want the one folded legacy admin", cfg.Admin.Users)
	}
	if !cfg.Admin.Require2FA {
		t.Error("require_2fa: true did not parse into Require2FA")
	}
}

// A users file that can't be loaded must not stop Loupe from starting: the
// proxy keeps serving, and the console locks itself (see AuthError).
func TestLoadBytesToleratesBrokenAuthFile(t *testing.T) {
	tests := []struct {
		name    string
		content *string // nil = file missing
		wantErr string
	}{
		{"broken yaml", strPtr("users: [unclosed"), "yaml"},
		{"invalid role", strPtr("users:\n  - username: pat\n    password_hash: \"$2a$10$abc\"\n    role: owner\n"), "unknown role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "admin_auth.yaml")
			if tt.content != nil {
				if err := os.WriteFile(path, []byte(*tt.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := LoadBytes([]byte("admin:\n  listen: 0.0.0.0:9090\n  auth_file: " + path + "\n"))
			if err != nil {
				t.Fatalf("LoadBytes = %v, want the config to load despite the users file", err)
			}
			if !strings.HasPrefix(cfg.Admin.AuthError, "admin.auth_file: ") || !strings.Contains(cfg.Admin.AuthError, tt.wantErr) {
				t.Errorf("AuthError = %q, want it to start with %q and mention %q", cfg.Admin.AuthError, "admin.auth_file: ", tt.wantErr)
			}
			if len(cfg.Admin.Users) != 0 {
				t.Errorf("Users = %+v, want none from a broken file", cfg.Admin.Users)
			}
		})
	}
}

// Without auth_file, the users file defaults into data_dir, so a console off
// loopback is never unauthenticated: until the file exists it offers setup.
func TestLoadBytesDefaultsAuthFileOffLoopback(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadBytes([]byte("data_dir: " + dir + "\nadmin:\n  listen: 0.0.0.0:9090\n"))
	if err != nil || cfg.Admin.AuthFile != filepath.Join(dir, "admin_auth.yaml") || !cfg.Admin.NeedsSetup {
		t.Fatalf("LoadBytes = %v, AuthFile %q, NeedsSetup %v; want the default file, needing setup", err, cfg.Admin.AuthFile, cfg.Admin.NeedsSetup)
	}
	cfg, err = LoadBytes([]byte("admin:\n  listen: 127.0.0.1:9090\n"))
	if err != nil || cfg.Admin.AuthError != "" {
		t.Fatalf("loopback without auth_file = %v, AuthError %q; want it allowed with no error", err, cfg.Admin.AuthError)
	}
}

func strPtr(s string) *string { return &s }
