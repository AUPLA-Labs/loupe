package main

// Credential setup for the admin dashboard: the interactive flow, and the
// user subcommands (the recovery path when an authenticator is lost). Kept
// separate from the main config.yaml: it's the only piece of this tool that
// ever sees a plaintext password, and it never has to round-trip that
// hand-commented file through a YAML marshaller (which would strip the
// comments) to make its edits. Only the interactive flow touches config.yaml.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"golang.org/x/term"
)

// userCommands are the `loupe -setup-admin <subcommand>` names, with the
// arguments each takes after its name.
var userCommands = map[string]string{
	"list-users":   "",
	"add-user":     "<name> <admin|viewer>",
	"set-role":     "<name> <admin|viewer>",
	"set-password": "<name>",
	"reset-2fa":    "<name>",
	"remove-user":  "<name>",
}

// setupAdminMain runs `loupe -setup-admin`; args is everything after it. The
// first argument is a subcommand only when it is exactly one of the names
// above, so `loupe -setup-admin config.yaml` keeps meaning the interactive
// setup of that config.
func setupAdminMain(args []string) error {
	cmd, rest, cfgPath, err := splitSetupArgs(args)
	if err != nil {
		return err
	}
	if cmd == "" {
		return runSetupAdmin(cfgPath)
	}
	_, _, authFile, err := readAdminSettings(cfgPath)
	if err != nil {
		return err
	}
	stdin := bufio.NewReader(os.Stdin)
	return runUserCommand(authFile, cmd, rest, func() (string, error) {
		return readPasswordTwice(stdin)
	})
}

// splitSetupArgs separates the optional subcommand, its arguments and the
// config path. -config (or --config, or -config=path) may appear anywhere
// after the subcommand; without a subcommand the first argument is the path.
func splitSetupArgs(args []string) (cmd string, rest []string, cfgPath string, err error) {
	cfgPath = "config.yaml"
	if len(args) == 0 {
		return "", nil, cfgPath, nil
	}
	if _, ok := userCommands[args[0]]; !ok {
		return "", nil, args[0], nil
	}
	cmd = args[0]
	for i := 1; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-config" || a == "--config":
			if i+1 >= len(args) {
				return "", nil, "", fmt.Errorf("%s needs a path", a)
			}
			i++
			cfgPath = args[i]
		case strings.HasPrefix(a, "-config="):
			cfgPath = strings.TrimPrefix(a, "-config=")
		case strings.HasPrefix(a, "--config="):
			cfgPath = strings.TrimPrefix(a, "--config=")
		default:
			rest = append(rest, a)
		}
	}
	return cmd, rest, cfgPath, nil
}

// readAdminSettings reads config.yaml and returns its raw bytes, the admin
// listen address and the users file: admin.auth_file, else data/admin_auth.yaml
// beside the config.
func readAdminSettings(cfgPath string) (raw []byte, adminListen, authFile string, err error) {
	raw, err = os.ReadFile(cfgPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("read %s: %w", cfgPath, err)
	}

	cfg, err := config.LoadBytes(raw)
	if err != nil {
		// The existing config may currently be invalid in exactly the way
		// this command fixes (listen exposed with no auth_file yet) — that's
		// fine to proceed from; anything else is a real problem to surface.
		fmt.Fprintf(os.Stderr, "note: current config does not load cleanly (%v) — continuing to fix it up\n", err)
	}
	adminListen = "127.0.0.1:9090"
	if cfg != nil {
		if cfg.Admin.Listen != "" {
			adminListen = cfg.Admin.Listen
		}
		authFile = cfg.Admin.AuthFile
	}
	if authFile == "" {
		authFile = filepath.Join("data", "admin_auth.yaml")
	}
	// Relative paths are the service's, whose working directory is the
	// config's folder (loupe.service); this command may run from anywhere.
	if !filepath.IsAbs(authFile) {
		authFile = filepath.Join(filepath.Dir(cfgPath), authFile)
	}
	return raw, adminListen, authFile, nil
}

func runSetupAdmin(cfgPath string) error {
	raw, adminListen, authFile, err := readAdminSettings(cfgPath)
	if err != nil {
		return err
	}

	// An existing users file (either layout) is extended; a missing one, or
	// one that is only whitespace, is created fresh. Anything else that fails
	// to load is left alone for the operator to look at. This first load only
	// fails early, before any prompt: a running Loupe rewrites the file as
	// people sign in, so it is read again just before it is saved.
	if _, err := loadOrEmptyAuth(authFile); err != nil {
		return fmt.Errorf("read %s: %w", authFile, err)
	}
	if err := ensureOwnAuthFile(authFile); err != nil {
		return err
	}

	stdin := bufio.NewReader(os.Stdin)

	fmt.Print("Admin username: ")
	username, err := stdin.ReadString('\n')
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	password, err := readPasswordTwice(stdin)
	if err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	// Check the name now (it can be invalid, or collide) so the operator
	// finds out before the LAN question rather than after it.
	if _, err := setPasswordOrAddAdmin(trialAuth(authFile), username, hash); err != nil {
		return err
	}

	fmt.Print("Allow access from other devices on your local network? [y/N]: ")
	lanAns, err := stdin.ReadString('\n')
	if err != nil {
		return err
	}
	wantLAN := strings.HasPrefix(strings.ToLower(strings.TrimSpace(lanAns)), "y")

	// Read the file again, as late as possible, so users or sign-in state
	// written by a running Loupe during the prompts are kept.
	auth, err := loadOrEmptyAuth(authFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", authFile, err)
	}
	if auth == nil {
		auth = &config.AdminAuth{}
	}
	setName, err := setPasswordOrAddAdmin(auth, username, hash)
	if err != nil {
		return err
	}
	if setName != "" {
		fmt.Printf("Set a new password for %s (role and 2FA unchanged).\n", setName)
	}
	if err := saveAuthFile(authFile, auth); err != nil {
		return err
	}
	fmt.Printf("Wrote credentials to %s\n", authFile)

	newListen := adminListen
	if wantLAN {
		_, port, err := net.SplitHostPort(adminListen)
		if err != nil || port == "" {
			port = "9090"
		}
		newListen = "0.0.0.0:" + port
	}

	patched, err := patchConfig(raw, authFile, newListen)
	if err != nil {
		return err
	}

	if _, err := config.LoadBytes(patched); err != nil {
		return fmt.Errorf("resulting config would be invalid, nothing was written: %w", err)
	}

	if err := os.WriteFile(cfgPath, patched, 0600); err != nil {
		return fmt.Errorf("write %s: %w", cfgPath, err)
	}
	// os.WriteFile only applies the mode bits to a newly-created file; force
	// it here since config.yaml (which may still hold a legacy inline
	// hmac_secret) almost certainly already exists with looser permissions.
	if err := os.Chmod(cfgPath, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", cfgPath, err)
	}

	fmt.Printf("Updated %s (admin.auth_file, admin.listen=%q).\n", cfgPath, newListen)
	if wantLAN {
		fmt.Println("The admin UI will be reachable from your local network once restarted.")
		fmt.Println("Make sure your router is not forwarding this port to the internet.")
	}
	fmt.Println("Restart Loupe for this to take effect:  sudo systemctl restart loupe")
	return nil
}

// geteuid is os.Geteuid; tests stand in another user.
var geteuid = os.Geteuid

// checkAuthFileOwner refuses to let the user euid replace the users file at
// path, described by info, when someone else owns it. The file is replaced,
// not edited in place, so the new copy would belong to euid with mode 0600:
// run with sudo, Loupe (running as its own user) could no longer read it.
func checkAuthFileOwner(path string, info os.FileInfo, euid int) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) == euid {
		return nil
	}
	name := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	return fmt.Errorf("%s is owned by uid %d; run this command as that user (for example: sudo -u %s loupe -setup-admin ...)", path, st.Uid, name)
}

// ensureOwnAuthFile checks that this process may replace the users file. A
// missing file is fine: it is created as the user running this.
func ensureOwnAuthFile(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return checkAuthFileOwner(path, info, geteuid())
}

// saveAuthFile is how the CLI writes the users file: only over a file this
// user owns, in a 0700 directory it creates if needed, with mode 0600.
func saveAuthFile(path string, a *config.AdminAuth) error {
	if err := ensureOwnAuthFile(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := config.SaveAdminAuth(path, a); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// trialAuth loads the users file for a trial run, or an empty one when there
// is none (or it can't be read, which the real load reports).
func trialAuth(path string) *config.AdminAuth {
	if a, err := loadOrEmptyAuth(path); err == nil && a != nil {
		return a
	}
	return &config.AdminAuth{}
}

// setPasswordOrAddAdmin gives an existing user (any case) the new hash,
// keeping their role and 2FA, or adds a new name as an admin. It returns the
// existing user's name, or "" when it added one, and validates the result.
func setPasswordOrAddAdmin(a *config.AdminAuth, username, hash string) (string, error) {
	existing := ""
	if i := findUser(a, username); i >= 0 {
		a.Users[i].PasswordHash = hash
		existing = a.Users[i].Username
	} else {
		a.Users = append(a.Users, config.AdminUser{Username: username, PasswordHash: hash, Role: config.RoleAdmin})
	}
	return existing, a.Validate()
}

// loadOrEmptyAuth loads the users file, returning nil for a file that is
// missing or holds only whitespace (older versions treated an empty file as
// "no auth"; it no longer loads, so setup recreates it). A file that doesn't
// parse or validate is an error that says how to start over.
func loadOrEmptyAuth(path string) (*config.AdminAuth, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	a, err := config.ParseAdminAuth(data)
	if err != nil {
		// Setup won't guess at a file it can't read; the operator can fix it
		// by hand, or move it aside and run setup again.
		return nil, fmt.Errorf("%w (delete the file to start over)", err)
	}
	return a, nil
}

// findUser returns the index of the user with this name, ignoring case
// (names are unique that way), or -1.
func findUser(a *config.AdminAuth, name string) int {
	for i, u := range a.Users {
		if strings.EqualFold(u.Username, name) {
			return i
		}
	}
	return -1
}

// hashPassword applies the dashboard's password rules and hashing, so a
// password set here signs in there.
func hashPassword(p string) (string, error) {
	h, err := config.HashPassword(p)
	if err != nil && !errors.Is(err, config.ErrPasswordLength) {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return h, err
}

// runUserCommand applies one user subcommand to the users file. Commands that
// set a password call readPassword, but only after the command has been
// checked against the file, so a typo in the name doesn't cost a password.
func runUserCommand(authFile, cmd string, args []string, readPassword func() (string, error)) error {
	a, err := config.LoadAdminAuth(authFile)
	if err != nil {
		return fmt.Errorf("read %s: %w (run `loupe -setup-admin` first to create it)", authFile, err)
	}
	if cmd != "list-users" {
		// Before any prompt, so the operator doesn't type a password in vain.
		if err := ensureOwnAuthFile(authFile); err != nil {
			return err
		}
	}

	hash := ""
	if cmd == "add-user" || cmd == "set-password" {
		dry := &config.AdminAuth{Users: append([]config.AdminUser(nil), a.Users...)}
		if _, err := applyUserCommand(dry, cmd, args, "$2dry-run"); err != nil {
			return err
		}
		password, err := readPassword()
		if err != nil {
			return err
		}
		if hash, err = hashPassword(password); err != nil {
			return err
		}
	}

	if hash != "" {
		// The prompts took a while, during which a running Loupe may have
		// rewritten the file (a sign-in records its TOTP step; the dashboard
		// edits users). Build on what is there now, not on the first read.
		a, err = config.LoadAdminAuth(authFile)
		if err != nil {
			return fmt.Errorf("read %s: %w", authFile, err)
		}
	}
	line, err := applyUserCommand(a, cmd, args, hash)
	if err != nil {
		return err
	}
	fmt.Println(line)
	if cmd == "list-users" {
		return nil
	}
	if err := saveAuthFile(authFile, a); err != nil {
		return err
	}
	fmt.Printf("Saved %s. A running Loupe picks this up within a second.\n", authFile)
	return nil
}

// applyUserCommand runs one user subcommand against a and returns the line to
// print. passwordHash is the bcrypt hash for add-user and set-password. a is
// changed only when the result validates.
func applyUserCommand(a *config.AdminAuth, cmd string, args []string, passwordHash string) (string, error) {
	argSpec, ok := userCommands[cmd]
	if !ok {
		return "", fmt.Errorf("unknown command %q", cmd)
	}
	want := len(strings.Fields(argSpec))
	if len(args) != want {
		return "", fmt.Errorf("usage: %s", strings.TrimSpace(cmd+" "+argSpec))
	}

	users := append([]config.AdminUser(nil), a.Users...)
	next := &config.AdminAuth{Users: users}

	var name string
	idx := -1
	if cmd != "list-users" && cmd != "add-user" {
		name = args[0]
		if idx = findUser(next, name); idx < 0 {
			return "", fmt.Errorf("no such user %q", name)
		}
	}

	var line string
	switch cmd {
	case "list-users":
		lines := make([]string, len(users))
		for i, u := range users {
			twoFA := "off"
			if u.TOTPSecret != "" {
				twoFA = "on"
			}
			lines[i] = fmt.Sprintf("%s  %s  2fa:%s", u.Username, u.Role, twoFA)
		}
		return strings.Join(lines, "\n"), nil
	case "add-user":
		users = append(users, config.AdminUser{Username: args[0], PasswordHash: passwordHash, Role: args[1]})
		line = fmt.Sprintf("Added %s as %s.", args[0], args[1])
	case "set-role":
		users[idx].Role = args[1]
		line = fmt.Sprintf("%s is now %s.", users[idx].Username, args[1])
	case "set-password":
		users[idx].PasswordHash = passwordHash
		line = fmt.Sprintf("Changed the password for %s.", users[idx].Username)
	case "reset-2fa":
		users[idx].TOTPSecret, users[idx].TOTPLastStep, users[idx].RecoveryHashes = "", 0, nil
		line = fmt.Sprintf("Cleared 2FA and recovery codes for %s. They can set it up again after signing in.", users[idx].Username)
	case "remove-user":
		line = fmt.Sprintf("Removed %s.", users[idx].Username)
		users = append(users[:idx], users[idx+1:]...)
		// Validate reports an empty list as "no users", which would hide the
		// real reason this is refused.
		admins := 0
		for _, u := range users {
			if u.Role == config.RoleAdmin {
				admins++
			}
		}
		if admins == 0 {
			return "", errors.New("at least one admin must remain")
		}
	}
	next.Users = users
	if err := next.Validate(); err != nil {
		return "", err
	}
	a.Users = users
	return line, nil
}

func readPasswordTwice(stdin *bufio.Reader) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("this must be run from an interactive terminal")
	}
	for {
		fmt.Print("Admin password: ")
		p1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		fmt.Print("Confirm password: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			fmt.Println("Passwords didn't match, try again.")
			continue
		}
		return string(p1), nil
	}
}

// patchConfig rewrites just the admin.auth_file and admin.listen lines (and
// the now-stale "no auth needed" comment above the admin: block, if present)
// within an existing config.yaml, leaving every other line — including
// comments and formatting — untouched.
func patchConfig(raw []byte, authFile, listen string) ([]byte, error) {
	raw = bytes.Replace(raw,
		[]byte("# Admin web UI — localhost only, no auth needed."),
		[]byte("# Admin web UI — requires login; see admin.auth_file."),
		1)

	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, l := range lines {
		if l == "admin:" {
			start = i
			break
		}
	}
	if start == -1 {
		return nil, fmt.Errorf("no top-level %q section found in config", "admin:")
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		end = i
		break
	}

	lines = setBlockKey(lines, start, end, "listen", listen)
	// setBlockKey above may have shifted indices if it inserted a line;
	// recompute end before the second edit.
	end = blockEnd(lines, start)
	lines = setBlockKey(lines, start, end, "auth_file", authFile)

	return []byte(strings.Join(lines, "\n")), nil
}

func blockEnd(lines []string, start int) int {
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		return i
	}
	return len(lines)
}

// setBlockKey replaces the value of "key: ..." within lines[start:end] if
// present, or inserts "  key: <value>" right after lines[start] otherwise.
func setBlockKey(lines []string, start, end int, key, value string) []string {
	newLine := fmt.Sprintf("  %s: %q", key, value)
	for i := start + 1; i < end; i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), key+":") {
			out := make([]string, len(lines))
			copy(out, lines)
			out[i] = newLine
			return out
		}
	}
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:start+1]...)
	out = append(out, newLine)
	out = append(out, lines[start+1:]...)
	return out
}
