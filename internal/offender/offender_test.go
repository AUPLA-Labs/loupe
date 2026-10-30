package offender

import (
	"testing"
	"time"
)

func TestBlocksAfterThreshold(t *testing.T) {
	tr := New(3, time.Minute)
	if tr.Blocked("1.2.3.4") {
		t.Fatal("should not be blocked initially")
	}
	tr.Fail("1.2.3.4")
	tr.Fail("1.2.3.4")
	if tr.Blocked("1.2.3.4") {
		t.Fatal("should not be blocked before reaching the threshold")
	}
	if justBlocked := tr.Fail("1.2.3.4"); !justBlocked {
		t.Error("expected Fail to report justBlocked=true on the triggering failure")
	}
	if !tr.Blocked("1.2.3.4") {
		t.Fatal("expected to be blocked after reaching the threshold")
	}
}

func TestSuccessResetsFailureCount(t *testing.T) {
	tr := New(3, time.Minute)
	tr.Fail("1.2.3.4")
	tr.Fail("1.2.3.4")
	tr.Success("1.2.3.4")
	tr.Fail("1.2.3.4")
	tr.Fail("1.2.3.4")
	if tr.Blocked("1.2.3.4") {
		t.Fatal("failure count should have reset after Success, so two more failures should not trigger a block")
	}
}

func TestBlockExpires(t *testing.T) {
	tr := New(1, 10*time.Millisecond)
	tr.Fail("1.2.3.4")
	if !tr.Blocked("1.2.3.4") {
		t.Fatal("expected to be blocked immediately")
	}
	time.Sleep(20 * time.Millisecond)
	if tr.Blocked("1.2.3.4") {
		t.Fatal("expected block to have expired")
	}
}

func TestIndependentPerIP(t *testing.T) {
	tr := New(2, time.Minute)
	tr.Fail("1.1.1.1")
	tr.Fail("1.1.1.1")
	if !tr.Blocked("1.1.1.1") {
		t.Fatal("1.1.1.1 should be blocked")
	}
	if tr.Blocked("2.2.2.2") {
		t.Fatal("2.2.2.2 should be unaffected by 1.1.1.1's failures")
	}
}

func TestIssuedFirstTimeReturnsZero(t *testing.T) {
	tr := New(5, time.Minute)
	if got := tr.Issued("1.2.3.4"); got != 0 {
		t.Fatalf("first Issued() should return 0 prior-unanswered, got %d", got)
	}
}

func TestIssuedAccumulatesWithoutAnswer(t *testing.T) {
	tr := New(5, time.Minute)
	tr.Issued("1.2.3.4") // 1st issuance, no prior
	if got := tr.Issued("1.2.3.4"); got != 1 {
		t.Fatalf("2nd Issued() with no Answered() between should return 1, got %d", got)
	}
	if got := tr.Issued("1.2.3.4"); got != 2 {
		t.Fatalf("3rd Issued() with no Answered() between should return 2, got %d", got)
	}
}

func TestAnsweredResetsCounter(t *testing.T) {
	tr := New(5, time.Minute)
	tr.Issued("1.2.3.4")
	tr.Issued("1.2.3.4")
	tr.Answered("1.2.3.4")
	if got := tr.Issued("1.2.3.4"); got != 0 {
		t.Fatalf("Issued() after Answered() should return 0, got %d", got)
	}
}

func TestIssuedAndAnsweredArePerKey(t *testing.T) {
	tr := New(5, time.Minute)
	tr.Issued("1.2.3.4")
	tr.Issued("1.2.3.4")
	if got := tr.Issued("5.6.7.8"); got != 0 {
		t.Fatalf("unanswered count leaked across keys, got %d", got)
	}
}

func TestAnsweredOnNeverIssuedKeyIsSafe(t *testing.T) {
	tr := New(5, time.Minute)
	tr.Answered("1.2.3.4") // must not panic
	if got := tr.Issued("1.2.3.4"); got != 0 {
		t.Fatalf("Issued() after a no-op Answered() should return 0, got %d", got)
	}
}

func TestAnsweredNoClearance_IncrementsAndReads(t *testing.T) {
	tr := New(5, time.Minute)
	if got := tr.AnsweredNoClearanceCount("1.2.3.4"); got != 0 {
		t.Fatalf("initial count = %d, want 0", got)
	}
	tr.IncrAnsweredNoClearance("1.2.3.4")
	tr.IncrAnsweredNoClearance("1.2.3.4")
	if got := tr.AnsweredNoClearanceCount("1.2.3.4"); got != 2 {
		t.Fatalf("count after two increments = %d, want 2", got)
	}
}

func TestAnsweredNoClearance_ClearResetsToZero(t *testing.T) {
	tr := New(5, time.Minute)
	tr.IncrAnsweredNoClearance("1.2.3.4")
	tr.IncrAnsweredNoClearance("1.2.3.4")
	tr.ClearAnsweredNoClearance("1.2.3.4")
	if got := tr.AnsweredNoClearanceCount("1.2.3.4"); got != 0 {
		t.Fatalf("count after Clear = %d, want 0", got)
	}
}

func TestAnsweredNoClearance_IndependentPerKey(t *testing.T) {
	tr := New(5, time.Minute)
	tr.IncrAnsweredNoClearance("1.1.1.1")
	tr.IncrAnsweredNoClearance("1.1.1.1")
	tr.IncrAnsweredNoClearance("1.1.1.1")
	if got := tr.AnsweredNoClearanceCount("2.2.2.2"); got != 0 {
		t.Fatalf("2.2.2.2 count = %d, want 0 (unaffected by 1.1.1.1)", got)
	}
}
