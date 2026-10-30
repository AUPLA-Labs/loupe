package rules

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A regexp costs microseconds per test on a User-Agent, hundreds of times more
// than a plain string operation, and most rules do not match most requests.
// The prefilter extracts from the pattern a small set of literal strings of
// which at least one must appear in any match. A string containing none of
// them cannot match, which is decided with strings.Contains instead of the
// regexp engine. A string that does contain one still goes through the regexp,
// so the answer is never different, only faster.

const (
	maxPrefilterLits = 16
	minPrefilterLen  = 2
)

type reqLit struct {
	s    string
	fold bool // s is lower-case ASCII and matches ignoring ASCII case
}

type prefilter struct {
	lits    []reqLit
	hasFold bool
}

// newPrefilter returns nil when the pattern has no usable required literals.
func newPrefilter(re *regexp.Regexp) *prefilter {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	lits, ok := requiredLits(parsed.Simplify())
	if !ok || len(lits) == 0 || len(lits) > maxPrefilterLits {
		return nil
	}
	p := &prefilter{lits: lits}
	for _, l := range lits {
		if len(l.s) < minPrefilterLen {
			return nil
		}
		p.hasFold = p.hasFold || l.fold
	}
	return p
}

// allows reports whether s could match the pattern. false is definite.
func (p *prefilter) allows(s string) bool {
	foldOK := false
	if p.hasFold {
		// Case folding in a regexp reaches beyond ASCII (the Kelvin sign
		// folds to k), so only ASCII input is decided here.
		foldOK = true
		for i := 0; i < len(s); i++ {
			if s[i] >= 0x80 {
				return true
			}
		}
	}
	for _, l := range p.lits {
		if l.fold {
			if foldOK && containsFold(s, l.s) {
				return true
			}
		} else if strings.Contains(s, l.s) {
			return true
		}
	}
	return false
}

// containsFold reports whether ASCII string s contains lit, which is
// lower-case ASCII, ignoring case.
func containsFold(s, lit string) bool {
	n := len(lit)
	first := lit[0]
	for i := 0; i+n <= len(s); i++ {
		if s[i]|0x20 != first && s[i] != first {
			continue
		}
		j := 1
		for ; j < n; j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lit[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

// requiredLits returns literals of which at least one appears in every
// string the expression matches, and false when it cannot say.
func requiredLits(re *syntax.Regexp) ([]reqLit, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		if !fold {
			for _, r := range re.Rune {
				if r == utf8.RuneError {
					return nil, false // matches any invalid byte, which Contains would not
				}
			}
			return []reqLit{{s: string(re.Rune)}}, len(re.Rune) > 0
		}
		var b strings.Builder
		for _, r := range re.Rune {
			if r >= 0x80 {
				return nil, false
			}
			b.WriteRune(unicode.ToLower(r))
		}
		return []reqLit{{s: b.String(), fold: true}}, b.Len() > 0
	case syntax.OpCapture:
		return requiredLits(re.Sub[0])
	case syntax.OpPlus:
		return requiredLits(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLits(re.Sub[0])
		}
	case syntax.OpConcat:
		// Every part is required, so any one part's literals will do:
		// take the set whose shortest literal is longest.
		var best []reqLit
		bestLen := 0
		for _, sub := range re.Sub {
			lits, ok := requiredLits(sub)
			if !ok {
				continue
			}
			if m := minLen(lits); m > bestLen || (m == bestLen && len(lits) < len(best)) {
				best, bestLen = lits, m
			}
		}
		return best, best != nil
	case syntax.OpAlternate:
		var all []reqLit
		for _, sub := range re.Sub {
			lits, ok := requiredLits(sub)
			if !ok {
				return nil, false
			}
			all = append(all, lits...)
		}
		return all, len(all) > 0
	}
	return nil, false
}

func minLen(lits []reqLit) int {
	m := len(lits[0].s)
	for _, l := range lits[1:] {
		if len(l.s) < m {
			m = len(l.s)
		}
	}
	return m
}
