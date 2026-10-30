// Package scripts tests the release and install scripts.
package scripts

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// release serves a fake release: latest, the binaries (a shell script that
// records its arguments) and SHA256SUMS, with sum as the
// binary's checksum (empty = the right one).
func release(t *testing.T, sum string) (url, record string) {
	return releaseOf(t, sum, "")
}

// releaseOf is release with extra shell code at the top of the binary.
func releaseOf(t *testing.T, sum, prelude string) (url, record string) {
	t.Helper()
	record = filepath.Join(t.TempDir(), "args")
	bin := []byte("#!/bin/sh\n" + prelude + "echo \"$@\" > " + record + "\n")
	if sum == "" {
		sum = fmt.Sprintf("%x", sha256.Sum256(bin))
	}
	// Both builds, since busybox sh runs its own uname rather than the stub.
	files := map[string]string{
		"/loupe/latest":                  "0.1.0\n",
		"/loupe/0.1.0/loupe-linux-arm64": string(bin),
		"/loupe/0.1.0/loupe-linux-amd64": string(bin),
		"/loupe/0.1.0/SHA256SUMS":        sum + "  loupe-linux-arm64\n" + sum + "  loupe-linux-amd64\n",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[r.URL.Path]; ok {
			w.Write([]byte(b))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/loupe", record
}

// stubs puts fake uname (machine arch) and id (root) first on PATH.
func stubs(t *testing.T, arch string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("uname", `case "$1" in -m) echo `+arch+`;; *) echo Linux;; esac`+"\n")
	write("id", "echo 0\n")
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func runScript(t *testing.T, base, arch string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	cmd := exec.Command("sh", append([]string{"install.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+stubs(t, arch), "LOUPE_BASE_URL="+base)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallScript(t *testing.T) {
	base, record := release(t, "")
	out, err := runScript(t, base, "aarch64", "--backend", "http://127.0.0.1:3000")
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(record); strings.TrimSpace(string(got)) != "install --backend http://127.0.0.1:3000" {
		t.Errorf("loupe ran with %q", got)
	}
}

func TestInstallScriptBadChecksum(t *testing.T) {
	base, record := release(t, strings.Repeat("ab", 32))
	out, err := runScript(t, base, "aarch64")
	if err == nil || !strings.Contains(out, "checksum") {
		t.Errorf("bad checksum: %v\n%s", err, out)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("loupe ran despite a bad checksum")
	}
}

func TestInstallScriptUnknownArch(t *testing.T) {
	base, record := release(t, "")
	out, err := runScript(t, base, "mips")
	if err == nil || !strings.Contains(out, "mips") {
		t.Errorf("mips: %v\n%s", err, out)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("loupe ran on an unknown machine")
	}
}

func TestInstallScriptIsPOSIX(t *testing.T) {
	if out, err := exec.Command("sh", "-n", "install.sh").CombinedOutput(); err != nil {
		t.Errorf("sh -n: %v\n%s", err, out)
	}
	if p, err := exec.LookPath("checkbashisms"); err == nil {
		if out, err := exec.Command(p, "install.sh").CombinedOutput(); err != nil {
			t.Errorf("checkbashisms: %s", out)
		}
	}
	if p, err := exec.LookPath("dash"); err == nil {
		if out, err := exec.Command(p, "-n", "install.sh").CombinedOutput(); err != nil {
			t.Errorf("dash -n: %s", out)
		}
	}
}

// On a BusyBox system (Alpine and friends): busybox sh, wget instead of
// curl, busybox sha256sum, and nothing else on PATH.
func TestInstallScriptBusybox(t *testing.T) {
	bb, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("no busybox")
	}
	base, record := release(t, "")
	dir := t.TempDir()
	for _, applet := range []string{"sh", "wget", "sha256sum", "grep", "tr", "mktemp", "rm", "chmod"} {
		if err := os.Symlink(bb, filepath.Join(dir, applet)); err != nil {
			t.Fatal(err)
		}
	}
	// busybox sh runs its own id, so the script sees a normal user and uses
	// sudo; this one just runs the command.
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte("#!"+bb+" sh\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := strings.Replace(stubs(t, "aarch64"), os.Getenv("PATH"), dir, 1)
	cmd := exec.Command(bb, "sh", "install.sh", "--yes")
	cmd.Env = []string{"PATH=" + path, "LOUPE_BASE_URL=" + base, "HOME=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("busybox: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(record); strings.TrimSpace(string(got)) != "install --yes" {
		t.Errorf("loupe ran with %q\n%s", got, out)
	}
}

// A binary that can't run where it was downloaded (/tmp mounted noexec)
// gets a message that says so, not a bare "Permission denied".
func TestInstallScriptNoexecTmp(t *testing.T) {
	base, record := releaseOf(t, "", "exit 126\n")
	out, err := runScript(t, base, "aarch64")
	if err == nil || !strings.Contains(out, "TMPDIR") {
		t.Errorf("noexec: %v\n%s", err, out)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("installer ran")
	}
}
