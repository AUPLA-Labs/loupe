package lumen

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

var testBase = Base{Work: 1000, MemoryMB: 1, MaxMemoryMB: 32, MaxLevel: MaxLevel}

func TestParamsForScalesWorkAndCapsMemory(t *testing.T) {
	b := Base{Work: 100000, MemoryMB: 8, MaxMemoryMB: 32, MaxLevel: MaxLevel}
	cases := []struct {
		l      Level
		work   int64
		memMB  int64
		served Level
	}{
		{Glow, 50000, 4, Glow},
		{Standard, 100000, 8, Standard},
		{Bright, 400000, 16, Bright},
		{Intense, 1600000, 32, Intense},
		{Blinding, 6400000, 32, Blinding},
		{Blinding + 3, 6400000, 32, Blinding},
	}
	for _, c := range cases {
		p := ParamsFor(c.l, b)
		if p.Level != c.served || p.Work != c.work || p.MemoryBytes() != c.memMB<<20 {
			t.Errorf("level %v: got level %v work %d mem %d MB, want %v %d %d MB",
				c.l, p.Level, p.Work, p.MemoryBytes()>>20, c.served, c.work, c.memMB)
		}
	}
}

func TestParamsForClampsToPageMaxLevel(t *testing.T) {
	b := Base{Work: 20000, MemoryMB: 2, MaxMemoryMB: 32, MaxLevel: Standard}
	if p := ParamsFor(Blinding, b); p.Level != Standard || p.Scored != Blinding || p.Work != 20000 {
		t.Errorf("pulse at Blinding = %+v, want served at Standard, scored Blinding", p)
	}
}

func TestLogNRoundsDownToPowerOfTwo(t *testing.T) {
	for mb, want := range map[float64]uint8{0.5: 10, 1: 10, 2: 11, 3: 11, 4: 12, 8: 13, 16: 14, 32: 15} {
		if got := logNForMB(mb); got != want {
			t.Errorf("logNForMB(%v) = %d, want %d", mb, got, want)
		}
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	c, err := New(ParamsFor(Standard, testBase))
	if err != nil {
		t.Fatal(err)
	}
	a, ok := Solve(c.Client())
	if !ok {
		t.Fatal("no solution found")
	}
	parsed, ok := ParseAnswer(a.Wire())
	if !ok {
		t.Fatal("answer didn't parse")
	}
	if !c.CheckWork(parsed) {
		t.Fatal("correct work rejected")
	}
	v := NewVerifier(1)
	if ok, err := v.CheckSpace(context.Background(), c, parsed); err != nil || !ok {
		t.Fatalf("correct space rejected: ok=%v err=%v", ok, err)
	}
}

func TestWrongAnswersRejected(t *testing.T) {
	c, _ := New(ParamsFor(Standard, testBase))
	a, _ := Solve(c.Client())
	v := NewVerifier(1)

	bad := a
	bad.Numbers = append([]int64{}, a.Numbers...)
	bad.Numbers[0]++
	if c.CheckWork(bad) {
		t.Error("wrong number accepted")
	}
	if c.CheckWork(Answer{Numbers: a.Numbers[:1]}) {
		t.Error("too few numbers accepted")
	}

	flipped := []byte(a.Digest)
	if flipped[0] == '0' {
		flipped[0] = '1'
	} else {
		flipped[0] = '0'
	}
	bad = a
	bad.Digest = string(flipped)
	if ok, _ := v.CheckSpace(context.Background(), c, bad); ok {
		t.Error("wrong digest accepted")
	}
	bad.Digest = ""
	if ok, _ := v.CheckSpace(context.Background(), c, bad); ok {
		t.Error("missing digest accepted")
	}
}

func TestSpaceDependsOnWorkAnswers(t *testing.T) {
	c, _ := New(ParamsFor(Standard, testBase))
	a, _ := Solve(c.Client())
	other, _ := Space(c.SpaceSalt, []int64{0, 0, 0, 0}, c.LogN)
	if hex.EncodeToString(other) == a.Digest {
		t.Fatal("space digest doesn't depend on the work answers")
	}
}

func TestCheckSpaceBusy(t *testing.T) {
	c, _ := New(ParamsFor(Standard, testBase))
	a, _ := Solve(c.Client())
	v := NewVerifier(1)
	v.slots <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.CheckSpace(ctx, c, a); err != ErrBusy {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}

func TestParseAnswerRejectsJunk(t *testing.T) {
	for _, raw := range []interface{}{
		nil, "x", map[string]interface{}{},
		map[string]interface{}{"n": []interface{}{}},
		map[string]interface{}{"n": []interface{}{-1.0}},
		map[string]interface{}{"n": []interface{}{1.5}},
		map[string]interface{}{"n": []interface{}{"1"}},
		map[string]interface{}{"n": []interface{}{1e300}},
	} {
		if _, ok := ParseAnswer(raw); ok {
			t.Errorf("ParseAnswer(%v) accepted", raw)
		}
	}
}

func TestScoreAndLevels(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want Level
	}{
		{"clean visitor", Inputs{}, Glow},
		{"one header oddity", Inputs{RequestScore: 2}, Standard},
		{"datacenter", Inputs{Datacenter: true}, Standard},
		{"datacenter, escalated", Inputs{Datacenter: true, Escalation: tier.SingleClick}, Bright},
		{"pressured ip", Inputs{IPPressure: 20}, Intense},
		{"malformed ua plus missing sec-fetch", Inputs{RequestScore: 9}, Blinding},
		{"fishing", Inputs{Unanswered: 10}, Bright},
		{"hot residential asn alone", Inputs{ASNHot: true}, Standard},
	}
	for _, c := range cases {
		score, _ := Score(c.in)
		if got := LevelFor(score); got != c.want {
			t.Errorf("%s: score %d → %v, want %v", c.name, score, got, c.want)
		}
	}
}

func TestLegacyWork(t *testing.T) {
	if got := LegacyWork(1000, 0); got != 1000 {
		t.Errorf("no pressure = %d", got)
	}
	if got := LegacyWork(1000, 8); got != 4000 {
		t.Errorf("pressure 8 = %d, want 4000", got)
	}
	if got := LegacyWork(1000, 1000); got != 32000 {
		t.Errorf("capped = %d, want 32000", got)
	}
}
