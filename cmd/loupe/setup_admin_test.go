package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

const testHash = "$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"
const testSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

func testAuth() *config.AdminAuth {
	return &config.AdminAuth{Users: []config.AdminUser{
		{
			Username: "pat", PasswordHash: testHash, Role: config.RoleAdmin,
			TOTPSecret: testSecret, TOTPLastStep: 12345, RecoveryHashes: []string{testHash, testHash},
		},
		{Username: "sam", PasswordHash: testHash, Role: config.RoleViewer},
	}}
}

func TestCLIResetTwoFA(t *testing.T) {
	a := testAuth()
	if _, err := applyUserCommand(a, "reset-2fa", []string{"pat"}, ""); err != nil {
		t.Fatal(err)
	}
	u := a.Users[0]
	if u.TOTPSecret != "" || u.TOTPLastStep != 0 || len(u.RecoveryHashes) != 0 {
		t.Errorf("2FA not cleared: %+v", u)
	}
	if u.PasswordHash != testHash || u.Role != config.RoleAdmin {
		t.Errorf("password hash and role must be kept: %+v", u)
	}
}

func TestCLIAddUserRejectsDuplicate(t *testing.T) {
	a := testAuth()
	_, err := applyUserCommand(a, "add-user", []string{"Pat", "viewer"}, testHash)
	if err == nil || !strings.Contains(err.Error(), "duplicate username") {
		t.Fatalf("err = %v, want a duplicate username error", err)
	}
	if len(a.Users) != 2 {
		t.Errorf("a changed after a refused add: %+v", a.Users)
	}
}

func TestCLIRemoveLastAdminRefused(t *testing.T) {
	for name, a := range map[string]*config.AdminAuth{
		"with a viewer left": testAuth(),
		"only user":          {Users: testAuth().Users[:1]},
	} {
		want := testAuth()
		if name == "only user" {
			want = &config.AdminAuth{Users: testAuth().Users[:1]}
		}
		_, err := applyUserCommand(a, "remove-user", []string{"pat"}, "")
		if err == nil || !strings.Contains(err.Error(), "at least one admin must remain") {
			t.Fatalf("%s: err = %v, want 'at least one admin must remain'", name, err)
		}
		if !reflect.DeepEqual(a, want) {
			t.Errorf("%s: a changed after a refused removal: %+v", name, a.Users)
		}
	}
}

func TestCLIUpgradesLegacyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	legacy := "username: \"pat\"\npassword_hash: \"" + testHash + "\"\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := config.LoadAdminAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyUserCommand(a, "set-role", []string{"pat", "admin"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAdminAuth(path, a); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "users:") {
		t.Errorf("file not in the new format:\n%s", data)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "username:") || strings.HasPrefix(line, "password_hash:") {
			t.Errorf("legacy key still written: %q", line)
		}
	}
}

func TestCLIListUsers(t *testing.T) {
	a := testAuth()
	out, err := applyUserCommand(a, "list-users", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "pat  admin  2fa:on\nsam  viewer  2fa:off"
	if out != want {
		t.Errorf("list-users =\n%q\nwant\n%q", out, want)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	_, err := applyUserCommand(testAuth(), "frobnicate", nil, "")
	if err == nil || !strings.Contains(err.Error(), `unknown command "frobnicate"`) {
		t.Errorf("err = %v, want unknown command", err)
	}
}

func TestCLICommands(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		args    []string
		hash    string
		wantErr string
		check   func(t *testing.T, a *config.AdminAuth)
	}{
		{"add viewer", "add-user", []string{"kim", "viewer"}, testHash, "", func(t *testing.T, a *config.AdminAuth) {
			if len(a.Users) != 3 || a.Users[2].Username != "kim" || a.Users[2].Role != config.RoleViewer || a.Users[2].PasswordHash != testHash {
				t.Errorf("users = %+v", a.Users)
			}
		}},
		{"add bad role", "add-user", []string{"kim", "root"}, testHash, "unknown role", nil},
		{"add bad name", "add-user", []string{"k m", "viewer"}, testHash, "invalid username", nil},
		{"add missing args", "add-user", []string{"kim"}, testHash, "usage: add-user", nil},
		{"set-role demote last admin", "set-role", []string{"pat", "viewer"}, "", "at least one admin must remain", nil},
		{"set-role promote", "set-role", []string{"sam", "admin"}, "", "", func(t *testing.T, a *config.AdminAuth) {
			if a.Users[1].Role != config.RoleAdmin {
				t.Errorf("sam = %+v", a.Users[1])
			}
		}},
		{"set-role no user", "set-role", []string{"nobody", "admin"}, "", `no such user "nobody"`, nil},
		{"set-password keeps role and 2fa", "set-password", []string{"pat"}, "$2a$10$newnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnew", "", func(t *testing.T, a *config.AdminAuth) {
			u := a.Users[0]
			if u.PasswordHash == testHash || u.Role != config.RoleAdmin || u.TOTPSecret != testSecret || len(u.RecoveryHashes) != 2 {
				t.Errorf("pat = %+v", u)
			}
		}},
		{"set-password finds user case-insensitively", "set-password", []string{"SAM"}, "$2a$10$newnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnewnew", "", func(t *testing.T, a *config.AdminAuth) {
			if a.Users[1].PasswordHash == testHash {
				t.Error("sam's password not changed")
			}
		}},
		{"set-password no user", "set-password", []string{"nobody"}, testHash, `no such user "nobody"`, nil},
		{"reset-2fa no user", "reset-2fa", []string{"nobody"}, "", `no such user "nobody"`, nil},
		{"remove viewer", "remove-user", []string{"sam"}, "", "", func(t *testing.T, a *config.AdminAuth) {
			if len(a.Users) != 1 || a.Users[0].Username != "pat" {
				t.Errorf("users = %+v", a.Users)
			}
		}},
		{"remove no user", "remove-user", []string{"nobody"}, "", `no such user "nobody"`, nil},
		{"remove extra args", "remove-user", []string{"sam", "pat"}, "", "usage: remove-user", nil},
		{"list with args", "list-users", []string{"x"}, "", "usage: list-users", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuth()
			before := testAuth()
			out, err := applyUserCommand(a, tt.cmd, tt.args, tt.hash)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				if !reflect.DeepEqual(a, before) {
					t.Errorf("a changed by a failed command: %+v", a.Users)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out == "" {
				t.Error("no line to print")
			}
			tt.check(t, a)
		})
	}
}

func TestHashPasswordLimits(t *testing.T) {
	tests := []struct {
		pw string
		ok bool
	}{
		{"", false},
		{"1234567", false},
		{"12345678", true},
		{strings.Repeat("x", 100), true},
		{strings.Repeat("x", 256), true},
		{strings.Repeat("x", 257), false},
	}
	for _, tt := range tests {
		h, err := hashPassword(tt.pw)
		if tt.ok && (err != nil || !config.CheckPassword(h, tt.pw)) {
			t.Errorf("%d chars: err = %v, want a hash that verifies", len(tt.pw), err)
		}
		if !tt.ok && (err == nil || err.Error() != "password must be 8 to 256 characters") {
			t.Errorf("%d chars: err = %v, want 'password must be 8 to 256 characters'", len(tt.pw), err)
		}
	}
}

func TestSplitSetupArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCmd  string
		wantRest []string
		wantCfg  string
		wantErr  bool
	}{
		{"interactive default", nil, "", nil, "config.yaml", false},
		{"interactive with path", []string{"my.yaml"}, "", nil, "my.yaml", false},
		{"list", []string{"list-users"}, "list-users", nil, "config.yaml", false},
		{"config after", []string{"add-user", "kim", "viewer", "-config", "c.yaml"}, "add-user", []string{"kim", "viewer"}, "c.yaml", false},
		{"config between", []string{"set-role", "-config", "c.yaml", "kim", "admin"}, "set-role", []string{"kim", "admin"}, "c.yaml", false},
		{"config equals", []string{"reset-2fa", "--config=c.yaml", "kim"}, "reset-2fa", []string{"kim"}, "c.yaml", false},
		{"config without value", []string{"list-users", "-config"}, "", nil, "", true},
		{"path that looks like a near-miss", []string{"list-user"}, "", nil, "list-user", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, rest, cfg, err := splitSetupArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if cmd != tt.wantCmd || cfg != tt.wantCfg || !reflect.DeepEqual(rest, tt.wantRest) {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", cmd, rest, cfg, tt.wantCmd, tt.wantRest, tt.wantCfg)
			}
		})
	}
}

func TestRunUserCommandSavesAndAsksForPasswordLast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	if err := config.SaveAdminAuth(path, testAuth()); err != nil {
		t.Fatal(err)
	}
	asked := false
	ask := func() (string, error) { asked = true; return "correct horse", nil }

	// A command that is bound to fail must not make the operator type a password first.
	if err := runUserCommand(path, "add-user", []string{"PAT", "viewer"}, ask); err == nil {
		t.Fatal("want a duplicate error")
	}
	if asked {
		t.Error("password was requested before the command was checked")
	}

	if err := runUserCommand(path, "add-user", []string{"kim", "viewer"}, ask); err != nil {
		t.Fatal(err)
	}
	if !asked {
		t.Error("password was never requested")
	}
	a, err := config.LoadAdminAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Users) != 3 || a.Users[2].Username != "kim" || !strings.HasPrefix(a.Users[2].PasswordHash, "$2") {
		t.Errorf("users = %+v", a.Users)
	}

	bad := func() (string, error) { return "short", nil }
	if err := runUserCommand(path, "set-password", []string{"kim"}, bad); err == nil || !strings.Contains(err.Error(), "password must be 8 to 256 characters") {
		t.Errorf("err = %v, want the password length error", err)
	}
	failing := func() (string, error) { return "", errors.New("no terminal") }
	if err := runUserCommand(path, "set-password", []string{"kim"}, failing); err == nil {
		t.Error("want the prompt error")
	}

	if err := runUserCommand(path, "reset-2fa", []string{"pat"}, ask); err != nil {
		t.Fatal(err)
	}
	a, _ = config.LoadAdminAuth(path)
	if a.Users[0].TOTPSecret != "" {
		t.Errorf("2FA not reset on disk: %+v", a.Users[0])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestRunUserCommandMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.yaml")
	err := runUserCommand(path, "list-users", nil, nil)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want it to name the missing file", err)
	}
}

// A running Loupe rewrites the users file while the operator types a
// password; the command must build on the file as it is after the prompt.
func TestRunUserCommandKeepsChangesMadeDuringPrompt(t *testing.T) {
	for _, cmd := range []struct {
		name string
		args []string
		pass bool
	}{
		{"set-password", []string{"sam"}, true},
		{"add-user", []string{"kim", "viewer"}, true},
	} {
		t.Run(cmd.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "admin_auth.yaml")
			if err := config.SaveAdminAuth(path, testAuth()); err != nil {
				t.Fatal(err)
			}
			ask := func() (string, error) {
				// What Loupe does meanwhile: a dashboard user add, and a
				// sign-in recording the last used TOTP step.
				a, err := config.LoadAdminAuth(path)
				if err != nil {
					t.Fatal(err)
				}
				a.Users[0].TOTPLastStep = 99999
				a.Users = append(a.Users, config.AdminUser{Username: "lee", PasswordHash: testHash, Role: config.RoleViewer})
				if err := config.SaveAdminAuth(path, a); err != nil {
					t.Fatal(err)
				}
				return "correct horse", nil
			}
			if err := runUserCommand(path, cmd.name, cmd.args, ask); err != nil {
				t.Fatal(err)
			}
			a, err := config.LoadAdminAuth(path)
			if err != nil {
				t.Fatal(err)
			}
			if i := findUser(a, "lee"); i < 0 {
				t.Errorf("user added during the prompt was dropped: %+v", a.Users)
			}
			if a.Users[0].TOTPLastStep != 99999 {
				t.Errorf("TOTPLastStep = %d, the sign-in recorded during the prompt was reverted", a.Users[0].TOTPLastStep)
			}
			switch cmd.name {
			case "set-password":
				if a.Users[1].PasswordHash == testHash {
					t.Error("sam's password was not changed")
				}
			case "add-user":
				if findUser(a, "kim") < 0 {
					t.Errorf("kim was not added: %+v", a.Users)
				}
			}
		})
	}
}

func TestLoadOrEmptyAuth(t *testing.T) {
	legacy := "username: \"pat\"\npassword_hash: \"" + testHash + "\"\n"
	tests := []struct {
		name      string
		content   *string // nil = file missing
		wantNil   bool
		wantUsers int
		wantErr   string
	}{
		{"missing", nil, true, 0, ""},
		{"empty", ptr(""), true, 0, ""},
		{"whitespace", ptr(" \n\t\n"), true, 0, ""},
		{"comment only", ptr("# Managed by Loupe\n"), false, 0, "no users (delete the file to start over)"},
		{"broken", ptr("users: [unclosed"), false, 0, "yaml"},
		{"legacy", &legacy, false, 1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "admin_auth.yaml")
			if tt.content != nil {
				if err := os.WriteFile(path, []byte(*tt.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			a, err := loadOrEmptyAuth(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantNil != (a == nil) {
				t.Fatalf("auth = %+v, wantNil %v", a, tt.wantNil)
			}
			if a != nil && len(a.Users) != tt.wantUsers {
				t.Errorf("users = %+v, want %d", a.Users, tt.wantUsers)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// writeSetupConfig writes a config.yaml exposing the console beyond this
// machine with admin.auth_file at a path that is not the default one.
func writeSetupConfig(t *testing.T) (cfgPath, authFile string) {
	t.Helper()
	dir := t.TempDir()
	authFile = filepath.Join(dir, "elsewhere", "users.yaml")
	cfgPath = filepath.Join(dir, "config.yaml")
	body := "admin:\n  listen: \"0.0.0.0:9090\"\n  auth_file: \"" + authFile + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, authFile
}

// The CLI is how a broken or missing users file gets repaired, so it must
// find the configured file even though that file doesn't load.
func TestSetupAdminFindsConfiguredFileWhenBroken(t *testing.T) {
	for _, content := range []*string{nil, ptr("users: [unclosed")} {
		cfgPath, authFile := writeSetupConfig(t)
		if content != nil {
			if err := os.MkdirAll(filepath.Dir(authFile), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(authFile, []byte(*content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, _, got, err := readAdminSettings(cfgPath)
		if err != nil || got != authFile {
			t.Errorf("readAdminSettings = %q, %v; want the configured %q", got, err, authFile)
		}
	}
}

func TestSetupAdminRefusesBrokenFile(t *testing.T) {
	cfgPath, authFile := writeSetupConfig(t)
	if err := os.MkdirAll(filepath.Dir(authFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authFile, []byte("users: [unclosed"), 0600); err != nil {
		t.Fatal(err)
	}
	err := runSetupAdmin(cfgPath)
	if err == nil || !strings.Contains(err.Error(), authFile) || !strings.Contains(err.Error(), "delete the file to start over") {
		t.Fatalf("err = %v, want a refusal naming %s with the start-over hint", err, authFile)
	}
	if b, _ := os.ReadFile(authFile); string(b) != "users: [unclosed" {
		t.Errorf("the broken file was changed: %q", b)
	}
}

// ownedInfo is file info for a file owned by uid.
type ownedInfo struct {
	os.FileInfo
	uid uint32
}

func (o ownedInfo) Sys() any { return &syscall.Stat_t{Uid: o.uid} }

// Run with sudo, the CLI would replace the users file with one owned by root
// that Loupe, running as its own user, can't read.
func TestCheckAuthFileOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	if err := config.SaveAdminAuth(path, testAuth()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	me := os.Geteuid()
	myName := strconv.Itoa(me)
	if u, err := user.LookupId(myName); err == nil {
		myName = u.Username
	}
	tests := []struct {
		name string
		info os.FileInfo
		euid int
		want string // "" = allowed
	}{
		{"same user", info, me, ""},
		{"other user", info, me + 1, fmt.Sprintf("%s is owned by uid %d; run this command as that user (for example: sudo -u %s loupe -setup-admin ...)", path, me, myName)},
		{"owner unknown to the system", ownedInfo{info, 3999999}, me, fmt.Sprintf("%s is owned by uid 3999999; run this command as that user (for example: sudo -u 3999999 loupe -setup-admin ...)", path)},
		{"root over the service user", info, 0, fmt.Sprintf("%s is owned by uid %d; run this command as that user (for example: sudo -u %s loupe -setup-admin ...)", path, me, myName)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAuthFileOwner(path, tt.info, tt.euid)
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("err = %v, want the owner allowed", err)
			case tt.want != "" && (err == nil || err.Error() != tt.want):
				t.Fatalf("err = %v\nwant %s", err, tt.want)
			}
		})
	}
}

// asOtherUser makes the CLI believe it runs as another user (root, say).
func asOtherUser(t *testing.T) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { geteuid = old })
}

func TestRunUserCommandRefusesFileOwnedByOtherUser(t *testing.T) {
	for _, cmd := range []struct {
		name string
		args []string
	}{
		{"reset-2fa", []string{"pat"}},
		{"set-role", []string{"sam", "admin"}},
		{"remove-user", []string{"sam"}},
		{"set-password", []string{"sam"}},
		{"add-user", []string{"kim", "viewer"}},
	} {
		t.Run(cmd.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "admin_auth.yaml")
			if err := config.SaveAdminAuth(path, testAuth()); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			asOtherUser(t)
			asked := false
			err := runUserCommand(path, cmd.name, cmd.args, func() (string, error) { asked = true; return "correct horse", nil })
			if err == nil || !strings.Contains(err.Error(), "is owned by uid") {
				t.Fatalf("err = %v, want a refusal naming the owner", err)
			}
			if asked {
				t.Error("asked for a password before refusing")
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Error("the users file was changed")
			}
		})
	}
	// Listing writes nothing, so it is allowed.
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	if err := config.SaveAdminAuth(path, testAuth()); err != nil {
		t.Fatal(err)
	}
	asOtherUser(t)
	if err := runUserCommand(path, "list-users", nil, nil); err != nil {
		t.Errorf("list-users as another user = %v, want it allowed", err)
	}
}

func TestSetupAdminRefusesFileOwnedByOtherUser(t *testing.T) {
	cfgPath, authFile := writeSetupConfig(t)
	if err := os.MkdirAll(filepath.Dir(authFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAdminAuth(authFile, testAuth()); err != nil {
		t.Fatal(err)
	}
	asOtherUser(t)
	if err := runSetupAdmin(cfgPath); err == nil || !strings.Contains(err.Error(), authFile+" is owned by uid") {
		t.Fatalf("err = %v, want a refusal before any prompt", err)
	}
}

func TestSaveAuthFileIsPrivate(t *testing.T) {
	t.Run("new file in a new directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data", "admin_auth.yaml")
		if err := saveAuthFile(path, testAuth()); err != nil {
			t.Fatal(err)
		}
		wantMode(t, filepath.Dir(path), 0700)
		wantMode(t, path, 0600)
	})
	t.Run("existing loose file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "admin_auth.yaml")
		if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if err := saveAuthFile(path, testAuth()); err != nil {
			t.Fatal(err)
		}
		wantMode(t, path, 0600)
	})
	t.Run("other user's file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "admin_auth.yaml")
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		asOtherUser(t)
		if err := saveAuthFile(path, testAuth()); err == nil {
			t.Fatal("saved over another user's file")
		}
		if b, _ := os.ReadFile(path); string(b) != "x" {
			t.Errorf("file changed: %q", b)
		}
	})
}

func wantMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %v, want %v", path, got, want)
	}
}
