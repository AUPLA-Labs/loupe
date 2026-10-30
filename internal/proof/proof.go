// Package proof implements proof-of-execution challenges. Each challenge is a
// single-use, server-side record that the client can only answer by running
// the page's script in a real layout engine: signal field names are
// randomised per challenge, the signal blob is sealed with a per-challenge
// key, and the answer must include the rendered geometry of server-chosen CSS
// boxes and the computed value of a server-chosen colour.
//
// None of this is secret from a determined attacker — the key and the
// puzzle are in the page. What it removes is static replay: a canned signal
// blob posted by a client that never ran the page no longer verifies, so the
// JS-side detection behind it can no longer be skipped for free.
package proof

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/lumen"
)

// Kind separates challenges by the page that issued them, so a pulse
// challenge cannot be redeemed at /loupe/verify or vice versa.
type Kind uint8

const (
	KindPulse Kind = iota + 1
	KindChallenge
	// KindPrism carries only the Prism puzzle page's Lumen challenge; the
	// puzzle itself has its own signed token.
	KindPrism
)

// Canonical signal names for the answers every challenge must carry. They
// are randomised like every other field.
const (
	FieldRects = "proofRects"
	FieldColor = "proofColor"
	// FieldLumen carries the Lumen answer (lumen.ParseAnswer), so it is
	// sealed and renamed like the signals instead of riding in its own
	// form field.
	FieldLumen = "lumen"
)

// containerWidths are multiples of 100 so every percentage term in a box
// width resolves to a whole pixel count.
var containerWidths = []int{300, 400, 500, 600}

const (
	minBoxes = 3
	maxBoxes = 5

	// rectTolerance absorbs sub-pixel snapping at non-100% zoom levels.
	rectTolerance = 1.0
	// colorTolerance absorbs per-engine rounding in hsl()→rgb() conversion.
	colorTolerance = 1
)

// Transform is the non-translate part of a box's transform.
type Transform uint8

const (
	TransformNone Transform = iota
	TransformRotate90
	TransformScale2
)

// Box describes one absolutely positioned element of the layout puzzle.
type Box struct {
	Left, Top   int
	BasePx, Pct int // width: calc(BasePx px + Pct %)
	Height      int
	Padding     int
	Border      int
	Margin      int
	BorderBox   bool
	TX, TY      int
	Transform   Transform
}

// CSS renders the box's inline style. The client applies it verbatim and
// never needs to understand it.
func (b Box) CSS() string {
	sizing := "content-box"
	if b.BorderBox {
		sizing = "border-box"
	}
	tf := fmt.Sprintf("translate(%dpx, %dpx)", b.TX, b.TY)
	switch b.Transform {
	case TransformRotate90:
		tf += " rotate(90deg)"
	case TransformScale2:
		tf += " scale(2)"
	}
	return fmt.Sprintf(
		"position:absolute;left:%dpx;top:%dpx;width:calc(%dpx + %d%%);height:%dpx;"+
			"padding:%dpx;border:%dpx solid #000;margin:%dpx;box-sizing:%s;transform:%s",
		b.Left, b.Top, b.BasePx, b.Pct, b.Height, b.Padding, b.Border, b.Margin, sizing, tf)
}

// Rect is a box's bounding rectangle relative to the puzzle container.
type Rect struct{ X, Y, W, H float64 }

// Expected computes the rectangle a real layout engine reports for b inside
// a container of width containerW.
func (b Box) Expected(containerW int) Rect {
	w := b.BasePx + containerW*b.Pct/100
	h := b.Height
	bw, bh := w, h
	if !b.BorderBox {
		bw += 2 * (b.Padding + b.Border)
		bh += 2 * (b.Padding + b.Border)
	}
	// transform-origin is the centre of the border box, so the bounding
	// box stays centred on it after rotation or scaling.
	cx := float64(b.Left+b.Margin+b.TX) + float64(bw)/2
	cy := float64(b.Top+b.Margin+b.TY) + float64(bh)/2
	ew, eh := float64(bw), float64(bh)
	switch b.Transform {
	case TransformRotate90:
		ew, eh = eh, ew
	case TransformScale2:
		ew, eh = 2*ew, 2*eh
	}
	return Rect{X: cx - ew/2, Y: cy - eh/2, W: ew, H: eh}
}

// HSL is the colour puzzle input; the answer is its computed rgb() value.
type HSL struct{ H, S, L int }

func (c HSL) CSS() string { return fmt.Sprintf("hsl(%d, %d%%, %d%%)", c.H, c.S, c.L) }

// RGB converts per CSS Color 4 §7 and rounds each channel.
func (c HSL) RGB() [3]int {
	h := float64(c.H)
	s := float64(c.S) / 100
	l := float64(c.L) / 100
	f := func(n float64) int {
		k := math.Mod(n+h/30, 12)
		a := s * math.Min(l, 1-l)
		v := l - a*math.Max(-1, math.Min(math.Min(k-3, 9-k), 1))
		return int(math.Round(v * 255))
	}
	return [3]int{f(0), f(8), f(4)}
}

// Spec is the server-side record of one issued challenge.
type Spec struct {
	ID         string
	IP         string
	Kind       Kind
	Issued     time.Time
	expires    time.Time
	Seed       uint32
	Fields     map[string]string // canonical → obfuscated
	ContainerW int
	Boxes      []Box
	Color      HSL
	// Lumen is the proof-of-work and proof-of-space part, nil if none was
	// issued.
	Lumen *lumen.Challenge
	// Manual records that the challenge was issued for the single-click
	// flow. It is server state, so the client can't add or strip it.
	Manual bool
}

// Options are the per-issue settings beyond the layout puzzle.
type Options struct {
	Lumen  *lumen.Params // nil issues no Lumen challenge
	Manual bool
}

// ClientSpec is what the page receives. The seed is split into two halves
// that are XORed client-side so it never appears as one literal.
type ClientSpec struct {
	ID         string                 `json:"id"`
	K1         uint32                 `json:"a"`
	K2         uint32                 `json:"b"`
	Fields     map[string]string      `json:"f"`
	ContainerW int                    `json:"w"`
	Boxes      []string               `json:"x"`
	Color      string                 `json:"c"`
	Lumen      *lumen.ClientChallenge `json:"l,omitempty"`
}

// Client renders the spec for the page.
func (s *Spec) Client() ClientSpec {
	mask := randUint32()
	boxes := make([]string, len(s.Boxes))
	for i, b := range s.Boxes {
		boxes[i] = b.CSS()
	}
	cs := ClientSpec{
		ID:         s.ID,
		K1:         s.Seed ^ mask,
		K2:         mask,
		Fields:     s.Fields,
		ContainerW: s.ContainerW,
		Boxes:      boxes,
		Color:      s.Color.CSS(),
	}
	if s.Lumen != nil {
		lc := s.Lumen.Client()
		cs.Lumen = &lc
	}
	return cs
}

// keystream mirrors the client's xorshift32 generator.
func keystream(seed uint32, n int) []byte {
	x := seed
	if x == 0 {
		x = 0x9e3779b9
	}
	out := make([]byte, n)
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = byte(x)
	}
	return out
}

// Seal is the server-side mirror of the client's seal(); used by tests.
func (s *Spec) Seal(signals map[string]interface{}) (string, error) {
	obf := make(map[string]interface{}, len(signals))
	for k, v := range signals {
		if name, ok := s.Fields[k]; ok {
			obf[name] = v
		}
	}
	raw, err := json.Marshal(obf)
	if err != nil {
		return "", err
	}
	ks := keystream(s.Seed, len(raw))
	for i := range raw {
		raw[i] ^= ks[i]
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ErrUnsealable means the blob was not produced by this challenge's seal.
var ErrUnsealable = errors.New("proof: payload does not unseal")

// Unseal reverses the client's seal and maps obfuscated field names back to
// canonical ones. Names not issued for this challenge are dropped.
func (s *Spec) Unseal(sealed string) (map[string]interface{}, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) == 0 {
		return nil, ErrUnsealable
	}
	ks := keystream(s.Seed, len(raw))
	for i := range raw {
		raw[i] ^= ks[i]
	}
	var obf map[string]interface{}
	if err := json.Unmarshal(raw, &obf); err != nil {
		return nil, ErrUnsealable
	}
	out := make(map[string]interface{}, len(obf))
	for canon, name := range s.Fields {
		if v, ok := obf[name]; ok {
			out[canon] = v
		}
	}
	return out, nil
}

// CheckRects reports whether the client's reported rectangles (a JSON array
// of [x, y, w, h] arrays) match the expected layout.
func (s *Spec) CheckRects(raw interface{}) bool {
	arr, ok := raw.([]interface{})
	if !ok || len(arr) != len(s.Boxes) {
		return false
	}
	for i, b := range s.Boxes {
		want := b.Expected(s.ContainerW)
		got, ok := arr[i].([]interface{})
		if !ok || len(got) != 4 {
			return false
		}
		vals := [4]float64{want.X, want.Y, want.W, want.H}
		for j, v := range vals {
			f, ok := got[j].(float64)
			if !ok || math.Abs(f-v) > rectTolerance {
				return false
			}
		}
	}
	return true
}

// CheckColor reports whether the client's computed colour string matches.
func (s *Spec) CheckColor(raw interface{}) bool {
	str, ok := raw.(string)
	if !ok {
		return false
	}
	str = strings.TrimSpace(str)
	if !strings.HasPrefix(str, "rgb(") || !strings.HasSuffix(str, ")") {
		return false
	}
	// Accept both legacy comma and modern space separators, and fractional
	// channels, so a future engine's serialisation change can't fail every
	// visitor on that engine.
	parts := strings.FieldsFunc(str[4:len(str)-1], func(r rune) bool { return r == ',' || r == ' ' })
	if len(parts) != 3 {
		return false
	}
	want := s.Color.RGB()
	for i, p := range parts {
		f, err := strconv.ParseFloat(p, 64)
		if err != nil || math.Abs(f-float64(want[i])) > colorTolerance {
			return false
		}
	}
	return true
}

// Store holds issued challenges until they are consumed or expire.
type Store struct {
	mu  sync.Mutex
	m   map[string]*Spec
	max int
	now func() time.Time
}

// ErrFull is returned by Issue when the store is at capacity.
var ErrFull = errors.New("proof: store full")

// NewStore returns a store holding at most max outstanding challenges and
// starts its expiry sweeper.
func NewStore(max int) *Store {
	s := &Store{m: make(map[string]*Spec), max: max, now: time.Now}
	go s.sweepLoop()
	return s
}

// Issue creates and stores a challenge bound to ip. fields lists the
// canonical signal names the page will send; FieldRects, FieldColor and
// FieldLumen are always added.
func (s *Store) Issue(ip string, kind Kind, fields []string, ttl time.Duration, opt Options) (*Spec, error) {
	sp, err := newSpec(ip, kind, fields)
	if err != nil {
		return nil, err
	}
	sp.Manual = opt.Manual
	if opt.Lumen != nil {
		if sp.Lumen, err = lumen.New(*opt.Lumen); err != nil {
			return nil, err
		}
	}
	sp.Issued = s.now()
	sp.expires = sp.Issued.Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.max {
		s.sweepLocked()
		if len(s.m) >= s.max {
			return nil, ErrFull
		}
	}
	s.m[sp.ID] = sp
	return sp, nil
}

// Consume removes and returns the challenge with this id. It fails if the
// id is unknown, expired, of another kind, or bound to another IP; the
// challenge is spent in every case, so a guessed or replayed id can never
// be retried.
func (s *Store) Consume(id, ip string, kind Kind) (*Spec, bool) {
	s.mu.Lock()
	sp, ok := s.m[id]
	if ok {
		delete(s.m, id)
	}
	s.mu.Unlock()
	if !ok || sp.Kind != kind || sp.IP != ip || s.now().After(sp.expires) {
		return nil, false
	}
	return sp, true
}

// Len reports the number of outstanding challenges.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func (s *Store) sweepLoop() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		s.sweepLocked()
		s.mu.Unlock()
	}
}

func (s *Store) sweepLocked() {
	now := s.now()
	for id, sp := range s.m {
		if now.After(sp.expires) {
			delete(s.m, id)
		}
	}
}

func newSpec(ip string, kind Kind, fields []string) (*Spec, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	sp := &Spec{
		ID:         hex.EncodeToString(idBytes),
		IP:         ip,
		Kind:       kind,
		Seed:       randUint32() | 1,
		Fields:     make(map[string]string, len(fields)+3),
		ContainerW: containerWidths[randN(len(containerWidths))],
	}

	all := append(append([]string{}, fields...), FieldRects, FieldColor, FieldLumen)
	used := make(map[string]bool, len(all))
	for _, f := range all {
		if _, dup := sp.Fields[f]; dup {
			continue
		}
		name := randName()
		for used[name] {
			name = randName()
		}
		used[name] = true
		sp.Fields[f] = name
	}

	n := minBoxes + randN(maxBoxes-minBoxes+1)
	for i := 0; i < n; i++ {
		sp.Boxes = append(sp.Boxes, randBox(sp.ContainerW))
	}
	sp.Color = HSL{H: randN(360), S: 20 + randN(81), L: 15 + randN(71)}
	return sp, nil
}

func randBox(containerW int) Box {
	b := Box{
		Left:    randN(200),
		Top:     randN(200),
		BasePx:  20 + randN(80),
		Pct:     randN(31),
		Height:  20 + randN(100),
		Padding: randN(16),
		// Borders stay at 0–1px: engines snap border widths to whole
		// device pixels, so at fractional DPRs (125% Windows scaling) a
		// thicker border measures up to ~1.2px narrower than declared —
		// beyond rectTolerance. Padding and margin are never snapped.
		Border:    randN(2),
		Margin:    randN(16),
		BorderBox: randN(2) == 1,
		TX:        randN(81) - 40,
		TY:        randN(81) - 40,
		Transform: Transform(randN(3)),
	}
	if b.BorderBox {
		// A border-box size smaller than its padding+border is clamped by
		// the engine; keep the content box non-negative so no clamp applies.
		edge := 2 * (b.Padding + b.Border)
		if b.BasePx < edge {
			b.BasePx = edge
		}
		if b.Height < edge {
			b.Height = edge
		}
	}
	if b.Transform == TransformRotate90 {
		// Rotating about the centre shifts the box by (w-h)/2; keep that a
		// whole pixel so the expected rect has no half-pixel ambiguity.
		// Padding and border add equally to both axes, so only the content
		// sizes matter.
		w := b.BasePx + containerW*b.Pct/100
		if (w-b.Height)%2 != 0 {
			b.Height++
		}
	}
	return b
}

const nameAlphabet = "abcdefghijklmnopqrstuvwxyz"

func randName() string {
	b := make([]byte, 6)
	for i := range b {
		b[i] = nameAlphabet[randN(len(nameAlphabet))]
	}
	return string(b)
}

func randN(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return int(v.Int64())
}

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint32(b[:])
}
