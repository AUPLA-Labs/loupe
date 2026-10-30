package version

import (
	"strings"
	"testing"
)

func TestStringFromSource(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = ""
	if got := String(); !strings.HasPrefix(got, "dev") {
		t.Errorf("String() = %q, want dev…", got)
	}
	Version = "1.2.3"
	if got := String(); got != "1.2.3" {
		t.Errorf("String() = %q, want 1.2.3", got)
	}
}
