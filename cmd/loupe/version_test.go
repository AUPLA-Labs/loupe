package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// goTool finds the go command running these tests.
func goTool(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

func TestVersionLdflags(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "loupe")
	build := exec.Command(goTool(t), "build", "-ldflags", "-X github.com/AUPLA-Labs/loupe/internal/version.Version=1.2.3-test", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "-version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "loupe 1.2.3-test" {
		t.Errorf("-version = %q (%v), want \"loupe 1.2.3-test\"", out, err)
	}
}
