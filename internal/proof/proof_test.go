package proof

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/lumen"
)

var testFields = []string{"screenW", "webdriver", "languages"}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return &Store{m: make(map[string]*Spec), max: 10, now: time.Now}
}

// solve answers sp exactly as a real layout engine would.
func solve(sp *Spec) (rects []interface{}, color string) {
	for _, b := range sp.Boxes {
		r := b.Expected(sp.ContainerW)
		rects = append(rects, []interface{}{r.X, r.Y, r.W, r.H})
	}
	c := sp.Color.RGB()
	return rects, fmt.Sprintf("rgb(%d, %d, %d)", c[0], c[1], c[2])
}

func TestSealUnsealRoundTrip(t *testing.T) {
	s := newTestStore(t)
	sp, err := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]interface{}{"screenW": 1920.0, "webdriver": false, "languages": "de-AT,de", "notIssued": 1.0}
	sealed, err := sp.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sp.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if out["screenW"] != 1920.0 || out["webdriver"] != false || out["languages"] != "de-AT,de" {
		t.Errorf("round trip = %v", out)
	}
	if _, ok := out["notIssued"]; ok {
		t.Error("a field the challenge never named must be dropped")
	}
}

func TestUnsealRejectsCannedAndForeignBlobs(t *testing.T) {
	s := newTestStore(t)
	a, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	b, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})

	canned := base64.StdEncoding.EncodeToString([]byte(`{"screenW":1920,"webdriver":false}`))
	if _, err := a.Unseal(canned); err == nil {
		t.Error("a plain JSON blob must not unseal")
	}
	sealedForB, _ := b.Seal(map[string]interface{}{"screenW": 1920.0})
	if out, err := a.Unseal(sealedForB); err == nil && len(out) > 0 {
		t.Errorf("a blob sealed for another challenge must not yield signals, got %v", out)
	}
	if _, err := a.Unseal(""); err == nil {
		t.Error("an empty blob must not unseal")
	}
}

func TestConsumeIsSingleUseAndBound(t *testing.T) {
	s := newTestStore(t)
	sp, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	if _, ok := s.Consume(sp.ID, "1.2.3.4", KindPulse); !ok {
		t.Fatal("first Consume must succeed")
	}
	if _, ok := s.Consume(sp.ID, "1.2.3.4", KindPulse); ok {
		t.Error("second Consume must fail (single-use)")
	}

	sp, _ = s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	if _, ok := s.Consume(sp.ID, "5.6.7.8", KindPulse); ok {
		t.Error("Consume from another IP must fail")
	}
	if _, ok := s.Consume(sp.ID, "1.2.3.4", KindPulse); ok {
		t.Error("a failed Consume must still spend the challenge")
	}

	sp, _ = s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	if _, ok := s.Consume(sp.ID, "1.2.3.4", KindChallenge); ok {
		t.Error("Consume with the wrong kind must fail")
	}
}

func TestConsumeRejectsExpired(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	sp, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	s.now = func() time.Time { return now.Add(61 * time.Second) }
	if _, ok := s.Consume(sp.ID, "1.2.3.4", KindPulse); ok {
		t.Error("an expired challenge must not be consumable")
	}
}

func TestIssueRespectsCapacity(t *testing.T) {
	s := &Store{m: make(map[string]*Spec), max: 2, now: time.Now}
	for i := 0; i < 2; i++ {
		if _, err := s.Issue("1.2.3.4", KindPulse, nil, time.Minute, Options{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Issue("1.2.3.4", KindPulse, nil, time.Minute, Options{}); err != ErrFull {
		t.Errorf("err = %v, want ErrFull", err)
	}
}

func TestFieldNamesAreRandomisedAndUnique(t *testing.T) {
	s := newTestStore(t)
	a, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	b, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	if _, ok := a.Fields[FieldRects]; !ok {
		t.Error("FieldRects must always be named")
	}
	if _, ok := a.Fields[FieldColor]; !ok {
		t.Error("FieldColor must always be named")
	}
	seen := map[string]bool{}
	same := 0
	for k, v := range a.Fields {
		if seen[v] {
			t.Errorf("duplicate obfuscated name %q", v)
		}
		seen[v] = true
		if k == v {
			t.Errorf("field %q was not renamed", k)
		}
		if b.Fields[k] == v {
			same++
		}
	}
	if same == len(a.Fields) {
		t.Error("two challenges produced identical field maps")
	}
}

func TestBoxExpected(t *testing.T) {
	cases := []struct {
		name string
		box  Box
		cw   int
		want Rect
	}{
		{
			name: "content-box adds padding and border",
			box:  Box{Left: 10, Top: 20, BasePx: 50, Pct: 10, Height: 30, Padding: 5, Border: 1, Margin: 3},
			cw:   400, // width = 50 + 40 = 90; border box = 90 + 12 = 102
			want: Rect{X: 13, Y: 23, W: 102, H: 42},
		},
		{
			name: "border-box keeps declared size",
			box:  Box{Left: 10, Top: 20, BasePx: 50, Pct: 10, Height: 30, Padding: 5, Border: 1, Margin: 3, BorderBox: true},
			cw:   400,
			want: Rect{X: 13, Y: 23, W: 90, H: 30},
		},
		{
			name: "translate shifts",
			box:  Box{Left: 0, Top: 0, BasePx: 40, Height: 20, TX: -7, TY: 9},
			cw:   300,
			want: Rect{X: -7, Y: 9, W: 40, H: 20},
		},
		{
			name: "rotate90 swaps about the centre",
			box:  Box{Left: 0, Top: 0, BasePx: 40, Height: 20, Transform: TransformRotate90},
			cw:   300, // centre (20,10) → 20 wide, 40 tall
			want: Rect{X: 10, Y: -10, W: 20, H: 40},
		},
		{
			name: "scale2 doubles about the centre",
			box:  Box{Left: 0, Top: 0, BasePx: 40, Height: 20, Transform: TransformScale2},
			cw:   300,
			want: Rect{X: -20, Y: -10, W: 80, H: 40},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.box.Expected(c.cw); got != c.want {
				t.Errorf("Expected = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestHSLToRGB(t *testing.T) {
	cases := []struct {
		in   HSL
		want [3]int
	}{
		{HSL{0, 100, 50}, [3]int{255, 0, 0}},
		{HSL{120, 100, 25}, [3]int{0, 128, 0}},
		{HSL{240, 100, 50}, [3]int{0, 0, 255}},
		{HSL{0, 0, 50}, [3]int{128, 128, 128}},
		{HSL{210, 50, 40}, [3]int{51, 102, 153}},
	}
	for _, c := range cases {
		if got := c.in.RGB(); got != c.want {
			t.Errorf("%s → %v, want %v", c.in.CSS(), got, c.want)
		}
	}
}

func TestCheckAnswers(t *testing.T) {
	s := newTestStore(t)
	sp, _ := s.Issue("1.2.3.4", KindPulse, nil, time.Minute, Options{})
	rects, color := solve(sp)

	if !sp.CheckRects(rects) {
		t.Error("exact rects must pass")
	}
	if !sp.CheckColor(color) {
		t.Errorf("exact colour %q must pass", color)
	}

	// Sub-pixel snapping within tolerance.
	nudged := make([]interface{}, len(rects))
	for i, r := range rects {
		v := r.([]interface{})
		nudged[i] = []interface{}{v[0].(float64) + 0.6, v[1], v[2].(float64) - 0.6, v[3]}
	}
	if !sp.CheckRects(nudged) {
		t.Error("rects within tolerance must pass")
	}

	// What jsdom/happy-dom report: zeros.
	zeros := make([]interface{}, len(rects))
	for i := range zeros {
		zeros[i] = []interface{}{0.0, 0.0, 0.0, 0.0}
	}
	if sp.CheckRects(zeros) {
		t.Error("all-zero rects must fail")
	}
	if sp.CheckRects(rects[:len(rects)-1]) {
		t.Error("a missing rect must fail")
	}
	if sp.CheckRects(nil) {
		t.Error("absent rects must fail")
	}
	if sp.CheckColor("") || sp.CheckColor("hsl(0, 0%, 0%)") {
		t.Error("absent or unconverted colour must fail")
	}
}

func TestCheckColorAcceptsSerialisationVariants(t *testing.T) {
	sp := &Spec{Color: HSL{210, 50, 40}} // rgb(51, 102, 153)
	for _, s := range []string{"rgb(51, 102, 153)", "rgb(51 102 153)", "rgb(51.2, 102, 152.6)", "rgb(52, 101, 153)"} {
		if !sp.CheckColor(s) {
			t.Errorf("%q must pass", s)
		}
	}
	for _, s := range []string{"rgb(54, 102, 153)", "rgb(51, 102)", "rgba(51, 102, 153, 0.5)"} {
		if sp.CheckColor(s) {
			t.Errorf("%q must fail", s)
		}
	}
}

func TestGeneratedBoxesAreUnambiguous(t *testing.T) {
	s := &Store{m: make(map[string]*Spec), max: 10000, now: time.Now}
	for i := 0; i < 2000; i++ {
		sp, err := s.Issue("1.2.3.4", KindPulse, nil, time.Minute, Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range sp.Boxes {
			if b.Border > 1 {
				t.Fatalf("border %d > 1px would be snapped at fractional DPR", b.Border)
			}
			if b.BorderBox {
				edge := 2 * (b.Padding + b.Border)
				if b.BasePx < edge || b.Height < edge {
					t.Fatalf("border-box smaller than padding+border would be clamped: %+v", b)
				}
			}
			if b.Transform == TransformRotate90 {
				w := b.BasePx + sp.ContainerW*b.Pct/100
				if (w-b.Height)%2 != 0 {
					t.Fatalf("rotated box has a half-pixel offset: %+v cw=%d", b, sp.ContainerW)
				}
			}
		}
		s.Consume(sp.ID, "1.2.3.4", KindPulse)
	}
}

func TestIssueCarriesLumenAndManual(t *testing.T) {
	s := newTestStore(t)
	p := lumen.ParamsFor(lumen.Standard, lumen.Base{Work: 1000, MemoryMB: 1, MaxLevel: lumen.MaxLevel})
	sp, err := s.Issue("1.2.3.4", KindChallenge, testFields, time.Minute, Options{Lumen: &p, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if sp.Lumen == nil || !sp.Manual {
		t.Fatalf("spec lost its options: lumen=%v manual=%v", sp.Lumen, sp.Manual)
	}
	if _, ok := sp.Fields[FieldLumen]; !ok {
		t.Error("lumen answer field was not issued a name")
	}
	raw, _ := json.Marshal(sp.Client())
	var cs map[string]interface{}
	_ = json.Unmarshal(raw, &cs)
	l, ok := cs["l"].(map[string]interface{})
	if !ok || len(l["p"].([]interface{})) != p.Puzzles {
		t.Fatalf("client spec lumen = %v", cs["l"])
	}
	if _, leaked := cs["manual"]; leaked {
		t.Error("manual flag leaked into the client spec")
	}

	a, ok := lumen.Solve(*sp.Client().Lumen)
	if !ok || !sp.Lumen.CheckWork(a) {
		t.Fatal("client spec doesn't describe the server's puzzles")
	}

	plain, _ := s.Issue("1.2.3.4", KindPulse, testFields, time.Minute, Options{})
	if plain.Lumen != nil || plain.Client().Lumen != nil {
		t.Error("lumen issued without being asked for")
	}
}
