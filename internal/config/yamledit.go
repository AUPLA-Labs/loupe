package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Surgical config.yaml editing for the dashboard's settings form. Decoding to
// a yaml.Node and encoding it again would drop every blank line and comment
// alignment in a carefully hand-formatted file, so instead each edit locates
// the value with the YAML parser and rewrites only those bytes. Comments,
// spacing and everything not being changed stay exactly as they were.

// Edit sets one value. Path is the chain of mapping keys ("abuse",
// "rate_limit", "burst"). Exactly one of Scalar or List is used: Scalar is an
// already-rendered YAML scalar (see RenderString and friends); List replaces
// a whole sequence (IsList).
type Edit struct {
	Path   []string
	Scalar string
	List   []ListItem
	IsList bool
	// Comment, when set, replaces the value's trailing comment — for
	// comments that describe the value ("# 24 hours") and would otherwise go
	// stale. Leave empty to keep whatever comment is there.
	Comment string
}

// ListItem is one sequence entry with an optional trailing comment, which is
// how the config labels ASNs with their organisation.
type ListItem struct {
	Value   string // rendered scalar
	Comment string // without the leading "#"
}

func RenderInt(v int64) string     { return strconv.FormatInt(v, 10) }
func RenderFloat(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

var plainSafe = regexp.MustCompile(`^[A-Za-z_./][A-Za-z0-9_./:-]*$`)

// RenderString quotes s unless it's unambiguous as a plain YAML scalar.
func RenderString(s string) string {
	switch strings.ToLower(s) {
	case "", "true", "false", "yes", "no", "on", "off", "null", "~":
		return strconv.Quote(s)
	}
	if plainSafe.MatchString(s) {
		return s
	}
	return strconv.Quote(s)
}

// ApplyEdits applies edits to a YAML document and returns the new bytes.
// Each edit is applied to a fresh parse of the previous result, then the
// final document is re-parsed to confirm every edited path now holds what
// was asked for — a mismatch is an error, never a silently wrong file.
func ApplyEdits(src []byte, edits []Edit) ([]byte, error) {
	out := src
	for _, e := range edits {
		var err error
		if out, err = applyEdit(out, e); err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(e.Path, "."), err)
		}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(out, &root); err != nil {
		return nil, fmt.Errorf("edited config doesn't parse: %w", err)
	}
	for _, e := range edits {
		_, v, _ := lookup(&root, e.Path)
		if v == nil {
			return nil, fmt.Errorf("%s: missing after edit", strings.Join(e.Path, "."))
		}
		if err := checkValue(v, e); err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(e.Path, "."), err)
		}
	}
	return out, nil
}

func checkValue(v *yaml.Node, e Edit) error {
	decode := func(s string) any {
		var x any
		yaml.Unmarshal([]byte("v: "+s), &x)
		if m, ok := x.(map[string]any); ok {
			return m["v"]
		}
		return nil
	}
	var got any
	v.Decode(&got)
	if !e.IsList {
		if want := decode(e.Scalar); !reflect.DeepEqual(got, want) {
			return fmt.Errorf("verification failed: got %v, want %v", got, want)
		}
		return nil
	}
	gl, _ := got.([]any)
	if len(gl) != len(e.List) {
		return fmt.Errorf("verification failed: %d items, want %d", len(gl), len(e.List))
	}
	for i, it := range e.List {
		if want := decode(it.Value); !reflect.DeepEqual(gl[i], want) {
			return fmt.Errorf("verification failed: item %d is %v, want %v", i, gl[i], want)
		}
	}
	return nil
}

// lookup follows path through mappings. It returns the key and value nodes
// of the last element (nil if absent) and the deepest mapping reached.
func lookup(root *yaml.Node, path []string) (key, val, parent *yaml.Node) {
	n := root
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	for i, p := range path {
		if n.Kind != yaml.MappingNode {
			return nil, nil, nil
		}
		parent = n
		var next *yaml.Node
		for j := 0; j+1 < len(n.Content); j += 2 {
			if n.Content[j].Value == p {
				key, next = n.Content[j], n.Content[j+1]
				break
			}
		}
		if next == nil {
			return nil, nil, parent
		}
		if i == len(path)-1 {
			return key, next, parent
		}
		n = next
	}
	return nil, nil, parent
}

// lastLine is the last source line (1-based) n or any descendant occupies.
func lastLine(n *yaml.Node) int {
	l := n.Line
	for _, c := range n.Content {
		if cl := lastLine(c); cl > l {
			l = cl
		}
	}
	return l
}

func applyEdit(src []byte, e Edit) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	lines := strings.Split(string(src), "\n")
	key, val, _ := lookup(&root, e.Path)
	if key == nil {
		return insertMissing(&root, lines, e)
	}
	if e.IsList {
		return replaceList(lines, key, val, e.List)
	}
	if val.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("is not a single value")
	}
	return replaceScalar(lines, key, val, e.Scalar, e.Comment)
}

func joinLines(lines []string) []byte { return []byte(strings.Join(lines, "\n")) }

// scalarEnd returns the index just past the scalar token starting at col.
func scalarEnd(line string, col int, flow bool) int {
	if col >= len(line) {
		return col
	}
	switch line[col] {
	case '"':
		for i := col + 1; i < len(line); i++ {
			if line[i] == '\\' {
				i++
				continue
			}
			if line[i] == '"' {
				return i + 1
			}
		}
		return len(line)
	case '\'':
		for i := col + 1; i < len(line); i++ {
			if line[i] == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				return i + 1
			}
		}
		return len(line)
	}
	end := len(line)
	if i := strings.Index(line[col:], " #"); i >= 0 {
		end = col + i
	}
	if flow {
		if i := strings.IndexAny(line[col:end], ",}]"); i >= 0 {
			end = col + i
		}
	}
	return col + len(strings.TrimRight(line[col:end], " \t"))
}

func replaceScalar(lines []string, key, val *yaml.Node, rendered, comment string) ([]byte, error) {
	// An empty value ("key:" with nothing after it) has no token to replace.
	if val.Tag == "!!null" && val.Value == "" {
		li := key.Line - 1
		line := lines[li]
		colon := strings.Index(line[key.Column-1:], ":") + key.Column - 1
		rest := line[colon+1:]
		comment := ""
		if i := strings.Index(rest, "#"); i >= 0 {
			comment = "  " + rest[i:]
		}
		lines[li] = line[:colon+1] + " " + rendered + comment
		return joinLines(lines), nil
	}
	li, col := val.Line-1, val.Column-1
	line := lines[li]
	flow := strings.ContainsAny(line[:col], "{[")
	end := scalarEnd(line, col, flow)
	rest := line[end:]
	// Keep a trailing comment in its column where possible.
	if t := strings.TrimLeft(rest, " \t"); strings.HasPrefix(t, "#") {
		gap := len(rest) - len(t)
		want := col + (end - col) + gap // the comment's original column
		pad := want - (col + len(rendered))
		if pad < 1 {
			pad = 1
		}
		rest = strings.Repeat(" ", pad) + t
	}
	if comment != "" && !flow {
		pad := "  "
		if t := strings.TrimLeft(rest, " \t"); strings.HasPrefix(t, "#") {
			pad = rest[:len(rest)-len(t)]
		}
		rest = pad + "# " + comment
	}
	lines[li] = line[:col] + rendered + rest
	return joinLines(lines), nil
}

func renderItems(indent string, items []ListItem) []string {
	w := 0
	for _, it := range items {
		if it.Comment != "" && len(it.Value) > w {
			w = len(it.Value)
		}
	}
	out := make([]string, len(items))
	for i, it := range items {
		s := indent + "- " + it.Value
		if c := strings.TrimSpace(it.Comment); c != "" {
			s += strings.Repeat(" ", w-len(it.Value)+2) + "# " + c
		}
		out[i] = s
	}
	return out
}

// keyLineWithoutValue returns the key's line cut back to "key:", keeping any
// trailing comment.
func keyLineWithoutValue(line string, key *yaml.Node, suffix string) string {
	colon := strings.Index(line[key.Column-1:], ":") + key.Column - 1
	comment := ""
	if i := strings.Index(line[colon:], " #"); i >= 0 {
		comment = "  " + strings.TrimLeft(line[colon+i:], " ")
	}
	return line[:colon+1] + suffix + comment
}

func replaceList(lines []string, key, val *yaml.Node, items []ListItem) ([]byte, error) {
	if val.Kind != yaml.SequenceNode {
		if val.Kind == yaml.ScalarNode && val.Tag == "!!null" {
			val = &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle, Line: key.Line}
		} else {
			return nil, fmt.Errorf("is not a list")
		}
	}
	keyIdx := key.Line - 1
	indent := strings.Repeat(" ", key.Column-1+2)

	var start, stop int // lines [start, stop) of block items to remove
	if val.Style&yaml.FlowStyle != 0 {
		if lastLine(val) != key.Line {
			return nil, fmt.Errorf("multi-line inline lists aren't supported; edit config.yaml directly")
		}
		start, stop = keyIdx+1, keyIdx+1
	} else {
		start, stop = val.Line-1, lastLine(val)
		if len(val.Content) > 0 {
			indent = strings.Repeat(" ", val.Content[0].Column-1-2)
		}
	}
	suffix := ""
	if len(items) == 0 {
		suffix = " []"
	}
	newKey := keyLineWithoutValue(lines[keyIdx], key, suffix)
	out := append([]string{}, lines[:keyIdx]...)
	out = append(out, newKey)
	out = append(out, lines[keyIdx+1:start]...)
	out = append(out, renderItems(indent, items)...)
	out = append(out, lines[stop:]...)
	return joinLines(out), nil
}

// insertMissing adds a key that isn't in the file yet, creating parent
// mappings as needed, after the last line of the deepest existing parent.
func insertMissing(root *yaml.Node, lines []string, e Edit) ([]byte, error) {
	doc := root.Content[0]
	n, depth := doc, 0
	for depth < len(e.Path)-1 {
		_, v, _ := lookup(root, e.Path[:depth+1])
		if v == nil {
			break
		}
		if v.Kind != yaml.MappingNode || v.Style&yaml.FlowStyle != 0 {
			return nil, fmt.Errorf("%s isn't a block mapping; edit config.yaml directly", strings.Join(e.Path[:depth+1], "."))
		}
		n, depth = v, depth+1
	}
	indentN := 0
	if n != doc && len(n.Content) > 0 {
		indentN = n.Content[0].Column - 1
	} else if n != doc {
		k, _, _ := lookup(root, e.Path[:depth])
		indentN = k.Column - 1 + 2
	}
	var add []string
	for i := depth; i < len(e.Path); i++ {
		pad := strings.Repeat(" ", indentN+2*(i-depth))
		switch {
		case i < len(e.Path)-1:
			add = append(add, pad+e.Path[i]+":")
		case e.IsList && len(e.List) == 0:
			add = append(add, pad+e.Path[i]+": []")
		case e.IsList:
			add = append(add, pad+e.Path[i]+":")
			add = append(add, renderItems(pad+"  ", e.List)...)
		case e.Comment != "":
			add = append(add, pad+e.Path[i]+": "+e.Scalar+"  # "+e.Comment)
		default:
			add = append(add, pad+e.Path[i]+": "+e.Scalar)
		}
	}
	at := len(lines)
	if n != doc {
		at = lastLine(n)
	} else {
		for at > 0 && strings.TrimSpace(lines[at-1]) == "" {
			at--
		}
		if at > 0 {
			add = append([]string{""}, add...)
		}
	}
	out := append([]string{}, lines[:at]...)
	out = append(out, add...)
	out = append(out, lines[at:]...)
	return joinLines(out), nil
}

// ListComments returns each item's trailing comment for the list at path —
// e.g. the organisation names next to ASNs — keyed by the item's value.
func ListComments(src []byte, path ...string) map[string]string {
	var root yaml.Node
	if yaml.Unmarshal(src, &root) != nil {
		return nil
	}
	_, v, _ := lookup(&root, path)
	out := map[string]string{}
	if v == nil || v.Kind != yaml.SequenceNode {
		return out
	}
	for _, it := range v.Content {
		if c := strings.TrimSpace(strings.TrimPrefix(it.LineComment, "#")); c != "" {
			out[it.Value] = c
		}
	}
	return out
}
