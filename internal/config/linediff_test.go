package config

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLineDiff(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want []DiffLine
	}{
		{"identical", "a\nb\n", "a\nb\n", []DiffLine{{" ", "a"}, {" ", "b"}}},
		{"insert in middle", "a\nc\n", "a\nb\nc\n", []DiffLine{{" ", "a"}, {"+", "b"}, {" ", "c"}}},
		{"delete", "a\nb\nc\n", "a\nc\n", []DiffLine{{" ", "a"}, {"-", "b"}, {" ", "c"}}},
		{"replace line", "a\nb\nc\n", "a\nX\nc\n", []DiffLine{{" ", "a"}, {"-", "b"}, {"+", "X"}, {" ", "c"}}},
		{"empty a", "", "a\nb\n", []DiffLine{{"+", "a"}, {"+", "b"}}},
		{"empty b", "a\nb\n", "", []DiffLine{{"-", "a"}, {"-", "b"}}},
		{"both empty", "", "", nil},
		{"missing trailing newline", "a\nb", "a\nb\nc", []DiffLine{{" ", "a"}, {" ", "b"}, {"+", "c"}}},
		{"blank lines kept", "a\n\nb\n", "a\nb\n", []DiffLine{{" ", "a"}, {"-", ""}, {" ", "b"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LineDiff([]byte(tt.a), []byte(tt.b))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LineDiff(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDiffStat(t *testing.T) {
	d := LineDiff([]byte("a\nb\nc\nd\n"), []byte("a\nX\nY\nc\n"))
	added, removed := DiffStat(d)
	if added != 2 || removed != 2 {
		t.Errorf("DiffStat = +%d -%d, want +2 -2 (diff %v)", added, removed, d)
	}
	if a, r := DiffStat(nil); a != 0 || r != 0 {
		t.Errorf("DiffStat(nil) = +%d -%d, want 0 0", a, r)
	}
}

func TestLineDiffLargeInputBounded(t *testing.T) {
	const n = 20_000
	lines := func(prefix string, from, to int) string {
		var sb strings.Builder
		for i := from; i < to; i++ {
			fmt.Fprintf(&sb, "%s%d\n", prefix, i)
		}
		return sb.String()
	}
	tests := []struct {
		name               string
		a, b               string
		wantAdded, wantRem int
	}{
		// A 1000-line block in the middle changed: the middle's table is
		// 1000x1000, well under the cap.
		{"block in the middle",
			lines("k", 0, 9500) + lines("old", 0, 1000) + lines("k", 10500, n),
			lines("k", 0, 9500) + lines("new", 0, 1000) + lines("k", 10500, n),
			1000, 1000},
		// Nothing in common: 20000x20000 cells is over the cap.
		{"completely different", lines("a", 0, n), lines("b", 0, n), n, n},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			d := LineDiff([]byte(tt.a), []byte(tt.b))
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if elapsed > 2*time.Second {
				t.Errorf("LineDiff took %v, want under 2s", elapsed)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
				t.Errorf("LineDiff allocated %d MiB, want under 64", alloc>>20)
			}
			if added, removed := DiffStat(d); added != tt.wantAdded || removed != tt.wantRem {
				t.Errorf("DiffStat = +%d -%d, want +%d -%d", added, removed, tt.wantAdded, tt.wantRem)
			}
			if want := n + tt.wantAdded; len(d) != want {
				t.Errorf("len(diff) = %d, want %d", len(d), want)
			}
		})
	}
}
