package main

// `loupe install`: sets Loupe up as a systemd service on this machine. It
// creates the loupe user, /etc/loupe/config.yaml (only if there is none),
// /var/lib/loupe and the unit, then starts it and prints the setup link.
// Running it again is the upgrade: binary and unit are replaced, the config
// and data never are. Everything goes through system and root so tests can
// run it against a temporary directory.

import (
	"bufio"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/admin"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"golang.org/x/term"
)

//go:embed install.service
var unitFile string

// unitMarker starts every unit the installer writes, so it only ever
// replaces its own.
const unitMarker = "# Written by `loupe install`"

const (
	installBin    = "/usr/local/bin/loupe"
	installConfig = "/etc/loupe/config.yaml"
	installUnit   = "/etc/systemd/system/loupe.service"
	installData   = "/var/lib/loupe" // the unit's WorkingDirectory and StateDirectory
	serviceUser   = "loupe"
)

// system is what the installer needs from the machine.
type system interface {
	run(name string, args ...string) error
	output(name string, args ...string) (string, error)
	lookupUser(name string) bool
	isRoot() bool
	hasSystemd() bool
	portFree(addr string) bool
	chown(path, owner, group string) error
	executable() (string, error)
	sleep(time.Duration)
}

type installer struct {
	sys         system
	root        string // "/" for real; every installed path is joined onto it
	in          *bufio.Reader
	out         io.Writer
	interactive bool // may ask questions
}

func installMain(args []string) error {
	in := &installer{
		sys:         realSystem{},
		root:        "/",
		in:          bufio.NewReader(os.Stdin),
		out:         os.Stdout,
		interactive: term.IsTerminal(int(os.Stdin.Fd())),
	}
	return in.main(args)
}

func (in *installer) path(p string) string { return filepath.Join(in.root, p) }

func (in *installer) say(format string, args ...any) { fmt.Fprintf(in.out, format+"\n", args...) }

func (in *installer) main(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(in.out)
	backend := fs.String("backend", "", "address of the site Loupe protects, e.g. http://127.0.0.1:3000")
	listen := fs.String("listen", "", "where your reverse proxy reaches Loupe (default 127.0.0.1:8080)")
	adminListen := fs.String("admin-listen", "", "where the dashboard listens (default 0.0.0.0:9090)")
	yes := fs.Bool("yes", false, "don't ask; take the next free port when one is in use")
	printConfig := fs.Bool("print-config", false, "print a config for --backend and exit, for machines without systemd")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *yes {
		in.interactive = false
	}

	if *printConfig {
		if err := checkBackend(*backend); err != nil {
			return err
		}
		_, err := in.out.Write(exampleConfig(*backend, or(*listen, "127.0.0.1:8080"), or(*adminListen, "0.0.0.0:9090")))
		return err
	}
	if !in.sys.isRoot() {
		return errors.New("loupe install sets up a system service: run it with sudo")
	}
	if !in.sys.hasSystemd() {
		in.say(`loupe install needs systemd, which this machine doesn't run. To run Loupe under another init system:
  1. Copy this binary to %s.
  2. Write a config:  loupe install --print-config --backend http://127.0.0.1:3000 > %s
     (data_dir in it is %s; create that folder, owned by the user Loupe runs as).
  3. Start "%s %s" as that user from your init system, with %s as its working directory.`,
			installBin, installConfig, installData, installBin, installConfig, installData)
		return errors.New("no systemd")
	}

	// Decide everything before changing anything.
	if old, err := os.ReadFile(in.path(installUnit)); err == nil && !strings.HasPrefix(string(old), unitMarker) {
		return fmt.Errorf("%s exists and wasn't written by loupe install; it is left alone. Remove or rename it to install here", installUnit)
	}
	cfgBytes, err := os.ReadFile(in.path(installConfig))
	keep := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !keep {
		if *backend == "" {
			if !in.interactive {
				return errors.New("--backend is required, e.g. --backend http://127.0.0.1:3000")
			}
			fmt.Fprint(in.out, "Address of the site Loupe protects (e.g. http://127.0.0.1:3000): ")
			line, _ := in.in.ReadString('\n')
			*backend = strings.TrimSpace(line)
		}
		if err := checkBackend(*backend); err != nil {
			return err
		}
		l, err := in.pickAddr(or(*listen, "127.0.0.1:8080"), *listen != "")
		if err != nil {
			return err
		}
		a, err := in.pickAddr(or(*adminListen, "0.0.0.0:9090"), *adminListen != "")
		if err != nil {
			return err
		}
		cfgBytes = exampleConfig(*backend, l, a)
	} else if *backend != "" || *listen != "" || *adminListen != "" {
		in.say("note: %s exists, so --backend, --listen and --admin-listen are ignored; edit it instead", installConfig)
	}
	cfg, err := config.LoadBytes(cfgBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", installConfig, err)
	}

	if !in.sys.lookupUser(serviceUser) {
		shell := "/usr/sbin/nologin"
		if _, err := os.Stat(in.path(shell)); err != nil {
			shell = "/sbin/nologin"
		}
		if err := in.sys.run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", installData, "--shell", shell, serviceUser); err != nil {
			return fmt.Errorf("create user %s: %w", serviceUser, err)
		}
	}
	if err := in.installBinary(); err != nil {
		return err
	}
	// The dashboard saves the config by writing a new file next to it, so
	// the folder is the service user's too.
	if err := os.MkdirAll(in.path(filepath.Dir(installConfig)), 0o750); err != nil {
		return err
	}
	if err := in.sys.chown(in.path(filepath.Dir(installConfig)), serviceUser, serviceUser); err != nil {
		return err
	}
	if keep {
		in.say("kept %s", installConfig)
	} else {
		if err := os.WriteFile(in.path(installConfig), cfgBytes, 0o640); err != nil {
			return err
		}
		if err := in.sys.chown(in.path(installConfig), serviceUser, serviceUser); err != nil {
			return err
		}
		in.say("wrote %s", installConfig)
	}
	if err := os.MkdirAll(in.path(filepath.Dir(installUnit)), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(in.path(installUnit), []byte(unitFile), 0o644); err != nil {
		return err
	}
	for _, c := range [][]string{{"daemon-reload"}, {"enable", "loupe"}, {"restart", "loupe"}} {
		if err := in.sys.run("systemctl", c...); err != nil {
			return fmt.Errorf("systemctl %s: %w", strings.Join(c, " "), err)
		}
	}
	return in.report(cfg)
}

// installBinary puts the running executable at installBin, unless it is
// already the one running.
func (in *installer) installBinary() error {
	exe, err := in.sys.executable()
	if err != nil {
		return err
	}
	dst := in.path(installBin)
	if a, err := os.Stat(exe); err == nil {
		if b, err := os.Stat(dst); err == nil && os.SameFile(a, b) {
			return nil
		}
	}
	src, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".loupe-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// pickAddr returns addr if its port is free. Otherwise it offers the next
// free port (asking on a terminal), unless the address was given explicitly.
func (in *installer) pickAddr(addr string, explicit bool) (string, error) {
	if in.sys.portFree(addr) {
		return addr, nil
	}
	if explicit {
		return "", fmt.Errorf("%s is in use", addr)
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	port, _ := strconv.Atoi(p)
	next := ""
	for q := port + 1; q <= port+50; q++ {
		if a := net.JoinHostPort(host, strconv.Itoa(q)); in.sys.portFree(a) {
			next = strconv.Itoa(q)
			break
		}
	}
	if next == "" {
		return "", fmt.Errorf("ports %d to %d are in use; pass a free address with --listen or --admin-listen", port, port+50)
	}
	if !in.interactive {
		in.say("port %d is in use, using %s", port, next)
		return net.JoinHostPort(host, next), nil
	}
	fmt.Fprintf(in.out, "Port %d is in use. Use %s? [Y/n/other port] ", port, next)
	line, _ := in.in.ReadString('\n')
	switch ans := strings.TrimSpace(strings.ToLower(line)); ans {
	case "", "y", "yes":
		return net.JoinHostPort(host, next), nil
	case "n", "no":
		return "", errors.New("no port chosen")
	default:
		if _, err := strconv.ParseUint(ans, 10, 16); err != nil {
			return "", fmt.Errorf("%q is not a port", ans)
		}
		a := net.JoinHostPort(host, ans)
		if !in.sys.portFree(a) {
			return "", fmt.Errorf("%s is in use", a)
		}
		return a, nil
	}
}

// report waits for the service to come up and says what to do next. A
// service that doesn't stay up is an error, with its last log lines.
func (in *installer) report(cfg *config.Config) error {
	authDir := filepath.Dir(cfg.Admin.AuthFile)
	if !filepath.IsAbs(authDir) {
		authDir = filepath.Join(installData, authDir)
	}
	authPath := filepath.Join(authDir, filepath.Base(cfg.Admin.AuthFile))
	token := ""
	for range 20 {
		if b, err := os.ReadFile(in.path(filepath.Join(authDir, "setup_token"))); err == nil {
			token = strings.TrimSpace(string(b))
			break
		}
		if _, err := os.Stat(in.path(authPath)); err == nil {
			break
		}
		in.sys.sleep(500 * time.Millisecond)
	}
	// Twice, further apart than RestartSec, so a crash loop shows.
	for i := range 2 {
		if i > 0 {
			in.sys.sleep(6 * time.Second)
		}
		if st, _ := in.sys.output("systemctl", "is-active", "loupe"); strings.TrimSpace(st) != "active" {
			log, _ := in.sys.output("journalctl", "-u", "loupe", "-n", "20", "--no-pager")
			in.say("Loupe didn't start. Its last log lines:\n%s", log)
			return errors.New("loupe.service is not running")
		}
	}

	in.say("\nLoupe is running.\n")
	if token != "" {
		in.say("Create the first admin (the link works once):")
		for _, u := range admin.SetupLinks(cfg.Admin.Listen, token) {
			in.say("  %s", u)
		}
	} else if _, err := os.Stat(in.path(authPath)); err == nil {
		in.say("The dashboard (admins already set up):")
		for _, u := range admin.ConsoleURLs(cfg.Admin.Listen) {
			in.say("  %s", u)
		}
	} else {
		in.say("The setup link for the first admin will be in Loupe's log shortly: journalctl -u loupe | grep setup")
	}
	in.say(`The dashboard only answers %s (admin.allow in %s).
On a server with no private network: ssh -L 9090:127.0.0.1:9090 you@this-server, then use the 127.0.0.1 link.

Next, point your reverse proxy at http://%s and pass Host, X-Forwarded-For
and X-Forwarded-Proto. Setups for Caddy, nginx, Apache, HAProxy and Traefik:
https://github.com/AUPLA-Labs/loupe/blob/main/docs/proxy.md

Logs:   journalctl -u loupe -f
Users:  sudo -u %s %s -setup-admin list-users -config %s`,
		strings.Join(cfg.Admin.Allow, ", "), installConfig, cfg.Listen, serviceUser, installBin, installConfig)
	return nil
}

func checkBackend(b string) error {
	u, err := url.Parse(b)
	if b == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("backend %q: want a URL like http://127.0.0.1:3000", b)
	}
	return nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

type realSystem struct{}

func (realSystem) run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func (realSystem) output(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return string(b), err
}

func (realSystem) lookupUser(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func (realSystem) isRoot() bool { return os.Geteuid() == 0 }

func (realSystem) hasSystemd() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

func (realSystem) portFree(addr string) bool {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func (realSystem) chown(path, owner, group string) error {
	u, err := user.Lookup(owner)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(g.Gid)
	return os.Lchown(path, uid, gid)
}

func (realSystem) executable() (string, error) { return os.Executable() }

func (realSystem) sleep(d time.Duration) { time.Sleep(d) }
