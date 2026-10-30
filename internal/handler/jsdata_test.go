package handler

import (
	"strings"
	"testing"
)

func TestJSStringArray(t *testing.T) {
	got, err := jsStringArray([]string{"window.foo", `it's "quoted"`})
	if err != nil {
		t.Fatalf("jsStringArray: %v", err)
	}
	s := string(got)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		t.Fatalf("expected a JSON array literal, got %q", s)
	}
	if !strings.Contains(s, `"window.foo"`) {
		t.Errorf("missing expected entry, got %q", s)
	}
	// A literal double-quote in the source string must not break out of the
	// generated JS string literal.
	if !strings.Contains(s, `\"quoted\"`) {
		t.Errorf("quote was not escaped, got %q", s)
	}
}

func TestJSStringArrayEmpty(t *testing.T) {
	got, err := jsStringArray(nil)
	if err != nil {
		t.Fatalf("jsStringArray: %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("jsStringArray(nil) = %q, want []", got)
	}
}
