package config

import "strings"

// DiffLine is one line of a line diff. Op is " " for a line both sides have,
// "+" for one only in the new text and "-" for one only in the old.
type DiffLine struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// lineDiffMaxCells bounds the LCS table (about 16 MB of int32s). A changed
// middle larger than this is shown as removed then added, not aligned.
const lineDiffMaxCells = 4_000_000

// LineDiff compares a and b line by line. The common prefix and suffix are
// matched directly and only the middle between them goes through a longest
// common subsequence, whose table is capped at lineDiffMaxCells: past that the
// middle is emitted as all "-" lines then all "+" lines, so memory stays
// bounded whatever the request body holds. A final line with no trailing
// newline still counts as a line. Where a line changed, the "-" comes before
// the "+".
func LineDiff(a, b []byte) []DiffLine {
	al, bl := splitLines(a), splitLines(b)

	p := 0
	for p < len(al) && p < len(bl) && al[p] == bl[p] {
		p++
	}
	s := 0
	for s < len(al)-p && s < len(bl)-p && al[len(al)-1-s] == bl[len(bl)-1-s] {
		s++
	}

	var out []DiffLine
	for _, l := range al[:p] {
		out = append(out, DiffLine{" ", l})
	}
	out = append(out, middleDiff(al[p:len(al)-s], bl[p:len(bl)-s])...)
	for _, l := range al[len(al)-s:] {
		out = append(out, DiffLine{" ", l})
	}
	return out
}

// middleDiff is the LCS diff of the lines between the common prefix and suffix.
func middleDiff(al, bl []string) []DiffLine {
	var out []DiffLine
	if len(al)*len(bl) > lineDiffMaxCells {
		for _, l := range al {
			out = append(out, DiffLine{"-", l})
		}
		for _, l := range bl {
			out = append(out, DiffLine{"+", l})
		}
		return out
	}

	// lcs[i][j] is the common-subsequence length of al[i:] and bl[j:]. One
	// backing slice keeps it to a single allocation.
	w := len(bl) + 1
	cells := make([]int32, (len(al)+1)*w)
	lcs := func(i, j int) int32 { return cells[i*w+j] }
	for i := len(al) - 1; i >= 0; i-- {
		for j := len(bl) - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				cells[i*w+j] = lcs(i+1, j+1) + 1
			} else {
				cells[i*w+j] = max(lcs(i+1, j), lcs(i, j+1))
			}
		}
	}

	i, j := 0, 0
	for i < len(al) && j < len(bl) {
		switch {
		case al[i] == bl[j]:
			out = append(out, DiffLine{" ", al[i]})
			i++
			j++
		case lcs(i+1, j) >= lcs(i, j+1):
			out = append(out, DiffLine{"-", al[i]})
			i++
		default:
			out = append(out, DiffLine{"+", bl[j]})
			j++
		}
	}
	for ; i < len(al); i++ {
		out = append(out, DiffLine{"-", al[i]})
	}
	for ; j < len(bl); j++ {
		out = append(out, DiffLine{"+", bl[j]})
	}
	return out
}

// DiffStat counts the added and removed lines in a LineDiff result.
func DiffStat(d []DiffLine) (added, removed int) {
	for _, l := range d {
		switch l.Op {
		case "+":
			added++
		case "-":
			removed++
		}
	}
	return added, removed
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}
