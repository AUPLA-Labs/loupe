package lumen

import (
	"encoding/hex"
	"strconv"
)

// Solve answers cc the way proof.js does, by brute force. It exists for
// tests and the browser self-test page, which need real answers to
// server-issued challenges.
func Solve(cc ClientChallenge) (Answer, bool) {
	var a Answer
	for _, p := range cc.Puzzles {
		found := false
		for n := int64(0); n < p.Max; n++ {
			if sha256Hex(p.Salt+strconv.FormatInt(n, 10)) == p.Hash {
				a.Numbers = append(a.Numbers, n)
				found = true
				break
			}
		}
		if !found {
			return Answer{}, false
		}
	}
	d, err := Space(cc.SpaceSalt, a.Numbers, cc.LogN)
	if err != nil {
		return Answer{}, false
	}
	a.Digest = hex.EncodeToString(d)
	return a, true
}

// Wire renders a in the JSON shape the page seals ({"n","d","w","s"}).
func (a Answer) Wire() map[string]interface{} {
	nums := make([]interface{}, len(a.Numbers))
	for i, n := range a.Numbers {
		nums[i] = float64(n)
	}
	return map[string]interface{}{"n": nums, "d": a.Digest, "w": a.WorkMs, "s": a.SpaceMs}
}
