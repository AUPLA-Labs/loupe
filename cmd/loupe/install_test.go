package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeSystem records what the installer runs and answers its questions.
type fakeSystem struct {
	root    string
	cmds    []string
	users   map[string]bool
	notRoot bool
	noSD    bool
	busy    map[string]bool // addresses in use
	probed  []string
	active  string           // what is-active prints; "" = active
	onRun   func(cmd string) // after each command
	exe     string
	journal string
}

func (f *fakeSystem) run(name string, args ...string) error {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.cmds = append(f.cmds, cmd)
	if name == "useradd" {
		f.users["loupe"] = true
	}
	if f.onRun != nil {
		f.onRun(cmd)
	}
	return nil
}

func (f *fakeSystem) output(name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.cmds = append(f.cmds, cmd)
	switch name {
	case "systemctl":
		if f.active == "" {
			return "active\n", nil
		}
		return f.active + "\n", nil
	case "journalctl":
		return f.journal, nil
	}
	return "", nil
}

func (f *fakeSystem) lookupUser(name string) bool { return f.users[name] }
func (f *fakeSystem) isRoot() bool                { return !f.notRoot }
func (f *fakeSystem) hasSystemd() bool            { return !f.noSD }
func (f *fakeSystem) portFree(addr string) bool {
	f.probed = append(f.probed, addr)
	return !f.busy[addr]
}
func (f *fakeSystem) chown(path, owner, group string) error { return nil }
func (f *fakeSystem) executable() (string, error)           { return f.exe, nil }
func (f *fakeSystem) sleep(time.Duration)                   {}

func newFake(t *testing.T) *fakeSystem {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(t.TempDir(), "loupe-download")
	if err := os.WriteFile(exe, []byte("#!binary v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fakeSystem{root: root, users: map[string]bool{}, busy: map[string]bool{}, exe: exe}
}

// runInstall runs the installer against f with args and stdin.
func runInstall(t *testing.T, f *fakeSystem, stdin string, interactive bool, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	in := &installer{sys: f, root: f.root, in: bufio.NewReader(strings.NewReader(stdin)), out: &out, interactive: interactive}
	err := in.main(args)
	return out.String(), err
}

func readRoot(t *testing.T, f *fakeSystem, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallFresh(t *testing.T) {
	f := newFake(t)
	out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--yes")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	cfg := readRoot(t, f, "etc/loupe/config.yaml")
	if !strings.Contains(cfg, `backend: "http://127.0.0.1:3000"`) || !strings.Contains(cfg, `listen: "127.0.0.1:8080"`) || !strings.Contains(cfg, `listen: "0.0.0.0:9090"`) {
		t.Errorf("config:\n%s", cfg)
	}
	if st, _ := os.Stat(filepath.Join(f.root, "etc/loupe/config.yaml")); st.Mode().Perm() != 0o640 {
		t.Errorf("config mode %v, want 0640", st.Mode().Perm())
	}
	unit := readRoot(t, f, "etc/systemd/system/loupe.service")
	for _, want := range []string{"User=loupe", "ExecStart=/usr/local/bin/loupe /etc/loupe/config.yaml", "StateDirectory=loupe", "ReadWritePaths=/etc/loupe"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if got := readRoot(t, f, "usr/local/bin/loupe"); got != "#!binary v2" {
		t.Errorf("binary = %q", got)
	}
	var ran []string
	for _, c := range f.cmds {
		if !strings.HasPrefix(c, "systemctl is-active") {
			ran = append(ran, strings.Fields(c)[0]+" "+strings.Fields(c)[1])
		}
	}
	want := []string{"useradd --system", "systemctl daemon-reload", "systemctl enable", "systemctl restart"}
	if !slices.Equal(ran, want) {
		t.Errorf("commands = %v, want %v", ran, want)
	}
}

func TestInstallKeepsExistingConfig(t *testing.T) {
	f := newFake(t)
	f.users["loupe"] = true
	files := map[string]string{
		"etc/loupe/config.yaml":            "backend: \"http://10.0.0.5:80\"\nlisten: \"127.0.0.1:8090\"\ndata_dir: \"/var/lib/loupe\"\n",
		"var/lib/loupe/admin_auth.yaml":    "users: []\n# hand edit\n",
		"etc/systemd/system/loupe.service": "# Written by `loupe install`; old unit",
		"usr/local/bin/loupe":              "old binary",
	}
	for p, c := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(f.root, p)), 0o755)
		os.WriteFile(filepath.Join(f.root, p), []byte(c), 0o644)
	}
	out, err := runInstall(t, f, "", false, "--yes")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	for _, p := range []string{"etc/loupe/config.yaml", "var/lib/loupe/admin_auth.yaml"} {
		if got := readRoot(t, f, p); got != files[p] {
			t.Errorf("%s changed:\n%s", p, got)
		}
	}
	if readRoot(t, f, "etc/systemd/system/loupe.service") == files["etc/systemd/system/loupe.service"] || readRoot(t, f, "usr/local/bin/loupe") != "#!binary v2" {
		t.Error("unit or binary not replaced")
	}
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "useradd") }) {
		t.Error("useradd ran for an existing user")
	}
	if len(f.probed) != 0 {
		t.Errorf("probed ports %v with an existing config", f.probed)
	}
	if !strings.Contains(out, "kept /etc/loupe/config.yaml") || !strings.Contains(out, "127.0.0.1:8090") {
		t.Errorf("output doesn't say the config was kept, or names the wrong port:\n%s", out)
	}
}

func TestInstallRefusesWithoutSystemd(t *testing.T) {
	for name, f := range map[string]*fakeSystem{"no systemd": newFake(t), "not root": newFake(t)} {
		if name == "no systemd" {
			f.noSD = true
		} else {
			f.notRoot = true
		}
		out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--yes")
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if ents, _ := os.ReadDir(f.root); len(ents) != 0 || len(f.cmds) != 0 {
			t.Errorf("%s: wrote %v, ran %v", name, ents, f.cmds)
		}
		if name == "no systemd" && !strings.Contains(out, "--print-config") {
			t.Errorf("no manual steps:\n%s", out)
		}
	}
}

func TestInstallBackendValidation(t *testing.T) {
	for _, b := range []string{"ftp://x", "127.0.0.1:3000", "http://", ""} {
		f := newFake(t)
		if _, err := runInstall(t, f, "", false, "--backend", b, "--yes"); err == nil {
			t.Errorf("backend %q accepted", b)
		}
		if ents, _ := os.ReadDir(f.root); len(ents) != 0 {
			t.Errorf("backend %q: wrote %v", b, ents)
		}
	}
	// Asked for when not given, on a terminal.
	f := newFake(t)
	out, err := runInstall(t, f, "http://127.0.0.1:4000\n", true)
	if err != nil || !strings.Contains(readRoot(t, f, "etc/loupe/config.yaml"), "http://127.0.0.1:4000") {
		t.Errorf("prompted backend: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Address of the site Loupe protects") {
		t.Errorf("no prompt:\n%s", out)
	}
}

func TestInstallPicksFreePort(t *testing.T) {
	f := newFake(t)
	f.busy["127.0.0.1:8080"] = true
	out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readRoot(t, f, "etc/loupe/config.yaml"), `listen: "127.0.0.1:8081"`) || !strings.Contains(out, "port 8080 is in use, using 8081") {
		t.Errorf("busy port not moved:\n%s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:8081") {
		t.Errorf("proxy instructions don't name the chosen port:\n%s", out)
	}

	// Interactive: offered, and a typed port is taken.
	f = newFake(t)
	f.busy["0.0.0.0:9090"] = true
	if _, err := runInstall(t, f, "9200\n", true, "--backend", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readRoot(t, f, "etc/loupe/config.yaml"), `listen: "0.0.0.0:9200"`) {
		t.Error("typed admin port not used")
	}

	// An explicit busy port is an error, before anything is written.
	f = newFake(t)
	f.busy["127.0.0.1:7000"] = true
	if _, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--listen", "127.0.0.1:7000", "--yes"); err == nil {
		t.Error("explicit busy --listen accepted")
	}
	if ents, _ := os.ReadDir(f.root); len(ents) != 0 {
		t.Errorf("wrote %v", ents)
	}
}

func TestInstallReportsFailedStart(t *testing.T) {
	f := newFake(t)
	f.active = "activating"
	f.journal = "loupe[1]: listen tcp 127.0.0.1:8080: bind: address already in use\n"
	out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--yes")
	if err == nil {
		t.Fatal("a service that isn't running reported success")
	}
	if !strings.Contains(out, "address already in use") || strings.Contains(out, "Loupe is running") {
		t.Errorf("output:\n%s", out)
	}
}

func TestInstallPrintsSetupLink(t *testing.T) {
	f := newFake(t)
	f.onRun = func(cmd string) {
		if cmd == "systemctl restart loupe" {
			os.MkdirAll(filepath.Join(f.root, "var/lib/loupe"), 0o755)
			os.WriteFile(filepath.Join(f.root, "var/lib/loupe/setup_token"), []byte(strings.Repeat("ab", 32)+"\n"), 0o600)
		}
	}
	out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--admin-listen", "127.0.0.1:9090", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "http://127.0.0.1:9090/setup/"+strings.Repeat("ab", 32)) || !strings.Contains(out, "Loupe is running") {
		t.Errorf("output:\n%s", out)
	}
}

func TestInstallPrintConfig(t *testing.T) {
	f := newFake(t)
	f.noSD, f.notRoot = true, true
	out, err := runInstall(t, f, "", false, "--print-config", "--backend", "http://127.0.0.1:3000")
	if err != nil || !strings.Contains(out, `backend: "http://127.0.0.1:3000"`) {
		t.Errorf("print-config: %v\n%s", err, out)
	}
	if len(f.cmds) != 0 {
		t.Errorf("ran %v", f.cmds)
	}
}

// A loupe.service that `loupe install` didn't write (a hand-made setup, like
// production's) is never replaced.
func TestInstallRefusesForeignUnit(t *testing.T) {
	f := newFake(t)
	unit := filepath.Join(f.root, "etc/systemd/system/loupe.service")
	os.MkdirAll(filepath.Dir(unit), 0o755)
	os.WriteFile(unit, []byte("[Service]\nExecStart=/home/someone/loupe/loupe\n"), 0o644)
	out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--yes")
	if err == nil || !strings.Contains(out+err.Error(), "loupe.service") {
		t.Fatalf("foreign unit: err %v\n%s", err, out)
	}
	if got := readRoot(t, f, "etc/systemd/system/loupe.service"); !strings.Contains(got, "/home/someone") {
		t.Error("foreign unit replaced")
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/loupe")); err == nil || len(f.cmds) != 0 {
		t.Errorf("changed things anyway: %v", f.cmds)
	}
}

// No link yet and no users file: say where the link will show up, never
// that admins exist.
func TestInstallNoLinkYet(t *testing.T) {
	f := newFake(t)
	out, err := runInstall(t, f, "", false, "--backend", "http://127.0.0.1:3000", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "already set up") || !strings.Contains(out, "journalctl -u loupe | grep setup") {
		t.Errorf("output:\n%s", out)
	}
}

// With admins set up, the dashboard link is one people can open, never the
// wildcard listen address.
func TestInstallDashboardLinkOnUpgrade(t *testing.T) {
	f := newFake(t)
	f.users["loupe"] = true
	cfg := filepath.Join(f.root, "etc/loupe/config.yaml")
	os.MkdirAll(filepath.Dir(cfg), 0o750)
	os.WriteFile(cfg, []byte("backend: \"http://127.0.0.1:3000\"\ndata_dir: \"/var/lib/loupe\"\nadmin:\n  listen: \"0.0.0.0:9090\"\n"), 0o640)
	os.MkdirAll(filepath.Join(f.root, "var/lib/loupe"), 0o755)
	os.WriteFile(filepath.Join(f.root, "var/lib/loupe/admin_auth.yaml"), []byte("users: []\n"), 0o600)
	out, err := runInstall(t, f, "", false, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "0.0.0.0") || !strings.Contains(out, "http://127.0.0.1:9090") {
		t.Errorf("dashboard link:\n%s", out)
	}
}
