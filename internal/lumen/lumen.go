// Package lumen is Loupe's proof-of-work and proof-of-space check. Every
// challenge asks the browser for two things, chained so the cheap one gates
// the expensive one:
//
//   - Work: a few SHA-256 preimage searches. Each puzzle's secret number
//     lies in [0, max), so the expected cost is half the level's work,
//     spread over several puzzles so the solve time is steady enough to show
//     progress.
//   - Space: one scrypt evaluation keyed on the work answers, which costs
//     the level's memory for the duration of the solve. A farm solving many
//     challenges at once pays that memory per concurrent solve.
//
// Challenges live server-side inside a proof.Spec, so the secret numbers,
// the difficulty and the manual flag are never trusted from the client.
// Verifying work is a comparison; verifying space recomputes the scrypt,
// which is why Verifier bounds how many run at once.
package lumen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
)

// Level is how much a challenge costs the client. The tier ladder decides
// what a visitor has to do; the level decides how hard their device works.
type Level int

const (
	Glow Level = iota
	Standard
	Bright
	Intense
	Blinding
)

// MaxLevel is the highest level there is.
const MaxLevel = Blinding

func (l Level) String() string {
	switch l {
	case Glow:
		return "glow"
	case Standard:
		return "standard"
	case Bright:
		return "bright"
	case Intense:
		return "intense"
	case Blinding:
		return "blinding"
	}
	return "level(" + strconv.Itoa(int(l)) + ")"
}

// R is scrypt's block size parameter; memory is 128·R·N bytes.
const R = 8

// Base is the Standard level's cost for one page. The other levels scale
// from it (see ParamsFor).
type Base struct {
	Work        int64 // total SHA-256 search space at Standard
	MemoryMB    int   // scrypt memory at Standard
	MaxMemoryMB int   // memory ceiling for every level
	MaxLevel    Level // highest level this page may issue
}

// Params is one issued challenge's cost.
type Params struct {
	Level Level // the level served
	// Scored is the level the scoring chose, before the page's MaxLevel
	// clamp. It differs from Level on a clamped page and in shadow mode,
	// and is what the dashboard shows.
	Scored  Level
	Work    int64 // total search space across all puzzles
	Puzzles int
	LogN    uint8 // scrypt cost; memory = 128·R·2^LogN bytes
}

// MemoryBytes is the scrypt memory the client needs for p.
func (p Params) MemoryBytes() int64 { return 128 * R << p.LogN }

// Per-level multipliers on the Standard work and memory. Work keeps growing
// past the memory ceiling; memory stops there because the ceiling is set by
// what a real phone can allocate, and a bot can claim to be a phone.
var (
	workMul = [...]float64{0.5, 1, 4, 16, 64}
	memMul  = [...]float64{0.5, 1, 2, 4, 4}
)

// puzzleCount splits the work so the total solve time varies far less than
// one big puzzle's would.
const puzzleCount = 4

// minLogN is 1 MB; anything less isn't a meaningful memory cost.
const minLogN = 10

// ParamsFor returns the cost of level l on a page with base b. The level is
// clamped to b.MaxLevel.
func ParamsFor(l Level, b Base) Params {
	if l < Glow {
		l = Glow
	}
	if l > MaxLevel {
		l = MaxLevel
	}
	scored := l
	if l > b.MaxLevel {
		l = b.MaxLevel
	}
	work := int64(float64(b.Work) * workMul[l])
	if work < puzzleCount {
		work = puzzleCount
	}
	mem := float64(b.MemoryMB) * memMul[l]
	if b.MaxMemoryMB > 0 && mem > float64(b.MaxMemoryMB) {
		mem = float64(b.MaxMemoryMB)
	}
	return Params{Level: l, Scored: scored, Work: work, Puzzles: puzzleCount, LogN: logNForMB(mem)}
}

// logNForMB rounds mb down to a power of two and converts it to scrypt's
// cost parameter: 2^LogN · 128 · R bytes = 2^(LogN-10) MB at R = 8.
func logNForMB(mb float64) uint8 {
	n := uint8(minLogN)
	for float64(int64(1)<<(n+1-minLogN)) <= mb && n < 20 {
		n++
	}
	return n
}

// Puzzle is one SHA-256 search: find number in [0, Max) with
// SHA-256(Salt + decimal(number)) == Hash.
type Puzzle struct {
	Salt   string
	Hash   string
	Max    int64
	answer int64
}

// Challenge is one issued Lumen check, held server-side.
type Challenge struct {
	Params
	Puzzles   []Puzzle
	SpaceSalt string
}

// New issues a challenge at p.
func New(p Params) (*Challenge, error) {
	if p.Puzzles < 1 {
		p.Puzzles = 1
	}
	max := (p.Work + int64(p.Puzzles) - 1) / int64(p.Puzzles)
	if max < 1 {
		max = 1
	}
	c := &Challenge{Params: p}
	for i := 0; i < p.Puzzles; i++ {
		salt, err := randHex(12)
		if err != nil {
			return nil, err
		}
		n, err := rand.Int(rand.Reader, big.NewInt(max))
		if err != nil {
			return nil, fmt.Errorf("rand int: %w", err)
		}
		c.Puzzles = append(c.Puzzles, Puzzle{
			Salt:   salt,
			Hash:   hashHex(salt, n.Int64()),
			Max:    max,
			answer: n.Int64(),
		})
	}
	var err error
	if c.SpaceSalt, err = randHex(16); err != nil {
		return nil, err
	}
	return c, nil
}

// ClientPuzzle and ClientChallenge are what the page receives.
type ClientPuzzle struct {
	Salt string `json:"s"`
	Hash string `json:"h"`
	Max  int64  `json:"m"`
}

type ClientChallenge struct {
	Puzzles   []ClientPuzzle `json:"p"`
	LogN      uint8          `json:"n"`
	R         int            `json:"r"`
	SpaceSalt string         `json:"s"`
}

// Client renders c for the page.
func (c *Challenge) Client() ClientChallenge {
	cc := ClientChallenge{LogN: c.LogN, R: R, SpaceSalt: c.SpaceSalt}
	for _, p := range c.Puzzles {
		cc.Puzzles = append(cc.Puzzles, ClientPuzzle{Salt: p.Salt, Hash: p.Hash, Max: p.Max})
	}
	return cc
}

// Answer is the client's reply, carried inside the sealed signal blob.
type Answer struct {
	Numbers []int64
	Digest  string  // hex scrypt output; empty if the client couldn't compute it
	WorkMs  float64 // client-measured, informational
	SpaceMs float64 // client-measured, informational
}

// ParseAnswer reads the answer out of its unsealed JSON form:
// {"n": [numbers], "d": "hex", "w": workMs, "s": spaceMs}.
func ParseAnswer(raw interface{}) (Answer, bool) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return Answer{}, false
	}
	arr, ok := m["n"].([]interface{})
	if !ok || len(arr) == 0 || len(arr) > 64 {
		return Answer{}, false
	}
	var a Answer
	for _, v := range arr {
		f, ok := v.(float64)
		if !ok || f < 0 || f > 1<<53 || f != math.Trunc(f) {
			return Answer{}, false
		}
		a.Numbers = append(a.Numbers, int64(f))
	}
	a.Digest, _ = m["d"].(string)
	a.WorkMs, _ = m["w"].(float64)
	a.SpaceMs, _ = m["s"].(float64)
	return a, true
}

// CheckWork reports whether a solves every puzzle.
func (c *Challenge) CheckWork(a Answer) bool {
	if c == nil || len(a.Numbers) != len(c.Puzzles) {
		return false
	}
	for i, p := range c.Puzzles {
		if a.Numbers[i] != p.answer {
			return false
		}
	}
	return true
}

// Hashes is how many SHA-256 evaluations a sequential solver needed for a,
// for the server-side hash-rate measurement.
func (a Answer) Hashes() int64 {
	var n int64
	for _, v := range a.Numbers {
		n += v + 1
	}
	return n
}

// SpacePassword is the scrypt password for numbers: the work answers, so
// space can't be computed before the work is done or farmed out separately.
func SpacePassword(numbers []int64) []byte {
	b := make([]byte, 0, len(numbers)*8)
	for i, n := range numbers {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendInt(b, n, 10)
	}
	return b
}

func hashHex(salt string, n int64) string {
	return sha256Hex(salt + strconv.FormatInt(n, 10))
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
