package handler

import (
	"fmt"
	"math"
	"testing"
	"time"
)

const testPrismSecret = "test-hmac-secret-for-puzzle-tests"

func TestBuildParsePuzzleToken_RoundTrip(t *testing.T) {
	gaps := [prismNumGaps]prismGap{{100, 150}, {250, 200}, {350, 100}}
	token, err := buildPrismToken(42, gaps, 1, "1.2.3.4", testPrismSecret)
	if err != nil {
		t.Fatalf("buildPrismToken: %v", err)
	}

	pt, err := parsePrismToken(token, testPrismSecret)
	if err != nil {
		t.Fatalf("parsePrismToken: %v", err)
	}

	if pt.ImageID != 42 {
		t.Errorf("imageID: got %d want 42", pt.ImageID)
	}
	if pt.CorrectIdx != 1 {
		t.Errorf("correctIdx: got %d want 1", pt.CorrectIdx)
	}
	if pt.IP != "1.2.3.4" {
		t.Errorf("ip: got %q want 1.2.3.4", pt.IP)
	}
	for i, g := range gaps {
		if pt.Gaps[i] != g {
			t.Errorf("gap[%d]: got %+v want %+v", i, pt.Gaps[i], g)
		}
	}
	if pt.Expiry <= time.Now().Unix() {
		t.Errorf("expiry should be in the future, got %d", pt.Expiry)
	}
}

func TestParsePuzzleToken_TamperedHMAC(t *testing.T) {
	gaps := [prismNumGaps]prismGap{{100, 150}, {250, 200}, {350, 100}}
	token, _ := buildPrismToken(1, gaps, 0, "1.2.3.4", testPrismSecret)
	tampered := token[:len(token)-4] + "ZZZZ"
	_, err := parsePrismToken(tampered, testPrismSecret)
	if err == nil {
		t.Fatal("expected error for tampered HMAC, got nil")
	}
}

func TestParsePuzzleToken_WrongSecret(t *testing.T) {
	gaps := [prismNumGaps]prismGap{{100, 150}, {250, 200}, {350, 100}}
	token, _ := buildPrismToken(1, gaps, 0, "1.2.3.4", testPrismSecret)
	_, err := parsePrismToken(token, "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestParsePuzzleToken_ExpiryIsInFuture(t *testing.T) {
	gaps := [prismNumGaps]prismGap{{100, 150}, {250, 200}, {350, 100}}
	token, _ := buildPrismToken(1, gaps, 0, "1.2.3.4", testPrismSecret)
	pt, err := parsePrismToken(token, testPrismSecret)
	if err != nil {
		t.Fatalf("parsePrismToken: %v", err)
	}
	wantExpiry := time.Now().Unix() + prismTTL
	if math.Abs(float64(pt.Expiry-wantExpiry)) > 5 {
		t.Errorf("expiry off: got %d want ~%d", pt.Expiry, wantExpiry)
	}
}

func TestGenerateGaps_BoundsAndSeparation(t *testing.T) {
	for i := 0; i < 200; i++ {
		gaps, err := generateGaps()
		if err != nil {
			t.Fatalf("generateGaps iter %d: %v", i, err)
		}
		for a := 0; a < prismNumGaps; a++ {
			g := gaps[a]
			if g.X < prismEdge || g.X > prismImageW-prismEdge {
				t.Errorf("iter %d gap[%d].X=%d out of [%d,%d]",
					i, a, g.X, prismEdge, prismImageW-prismEdge)
			}
			if g.Y < prismEdge || g.Y > prismImageH-prismEdge {
				t.Errorf("iter %d gap[%d].Y=%d out of [%d,%d]",
					i, a, g.Y, prismEdge, prismImageH-prismEdge)
			}
			for b := a + 1; b < prismNumGaps; b++ {
				dx := float64(gaps[a].X - gaps[b].X)
				dy := float64(gaps[a].Y - gaps[b].Y)
				dist := math.Sqrt(dx*dx + dy*dy)
				if dist < prismGapMin {
					t.Errorf("iter %d gaps[%d] and gaps[%d] too close: %.1fpx < %dpx",
						i, a, b, dist, prismGapMin)
				}
			}
		}
	}
}

// validatePrismGaps returns a non-empty description of the first invariant
// violation found in gaps, or "" if gaps satisfies every bound and
// separation constraint.
func validatePrismGaps(gaps [prismNumGaps]prismGap) string {
	for a := 0; a < prismNumGaps; a++ {
		g := gaps[a]
		if g.X < prismEdge || g.X > prismImageW-prismEdge {
			return fmt.Sprintf("gap[%d].X=%d out of [%d,%d]", a, g.X, prismEdge, prismImageW-prismEdge)
		}
		if g.Y < prismEdge || g.Y > prismImageH-prismEdge {
			return fmt.Sprintf("gap[%d].Y=%d out of [%d,%d]", a, g.Y, prismEdge, prismImageH-prismEdge)
		}
		for b := a + 1; b < prismNumGaps; b++ {
			dx := float64(gaps[a].X - gaps[b].X)
			dy := float64(gaps[a].Y - gaps[b].Y)
			if dist := math.Sqrt(dx*dx + dy*dy); dist < prismGapMin {
				return fmt.Sprintf("gaps[%d] and gaps[%d] too close: %.1fpx < %dpx", a, b, dist, prismGapMin)
			}
		}
	}
	return ""
}

// TestGenerateGaps_TerminatesUnderStress pins generateGaps' termination.
// Before the restart-on-exhaustion fix, a bad first two points could make
// the box unsatisfiable, and the old implementation retried only the
// failing third point forever — an infinite, CPU-spinning loop that
// reproduced reliably under repeated calls and hung the whole test suite.
// This runs several thousand calls off the test goroutine so a regression
// fails with a clear timeout instead of hanging `go test` indefinitely.
func TestGenerateGaps_TerminatesUnderStress(t *testing.T) {
	const iterations = 5000
	done := make(chan error, 1)
	go func() {
		for i := 0; i < iterations; i++ {
			gaps, err := generateGaps()
			if err != nil {
				done <- fmt.Errorf("iter %d: generateGaps error: %w", i, err)
				return
			}
			if v := validatePrismGaps(gaps); v != "" {
				done <- fmt.Errorf("iter %d: %s", i, v)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("generateGaps did not complete %d calls within 30s — possible infinite-loop regression", iterations)
	}
}

// TestPrismFallbackGaps_SatisfyInvariants pins the fallback triple returned
// when random placement exhausts prismMaxRestarts: it must itself satisfy
// every bound and separation constraint it is standing in for.
func TestPrismFallbackGaps_SatisfyInvariants(t *testing.T) {
	if v := validatePrismGaps(prismFallbackGaps); v != "" {
		t.Fatalf("prismFallbackGaps invalid: %s", v)
	}
}

func TestPuzzleTolerance_WithinCorrectGap(t *testing.T) {
	// 24+24px diagonal from correct centre → ~33.9px, within 35px threshold.
	correct := prismGap{200, 160}
	dx := float64(correct.X+24) - float64(correct.X)
	dy := float64(correct.Y+24) - float64(correct.Y)
	dist := math.Sqrt(dx*dx + dy*dy)
	if dist > prismTolPx {
		t.Errorf("expected within tolerance: dist=%.1f > %d", dist, prismTolPx)
	}
}

func TestPuzzleTolerance_DecoyGapFails(t *testing.T) {
	// Two gaps that satisfy prismGapMin must be > prismTolPx apart.
	gapA := prismGap{200, 160}
	gapB := prismGap{gapA.X + prismGapMin, gapA.Y}
	dx := float64(gapB.X - gapA.X)
	dy := float64(gapB.Y - gapA.Y)
	dist := math.Sqrt(dx*dx + dy*dy)
	if dist <= prismTolPx {
		t.Errorf("decoy gap should be outside tolerance: dist=%.1f", dist)
	}
}
