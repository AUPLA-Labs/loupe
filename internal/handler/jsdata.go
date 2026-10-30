package handler

import (
	"encoding/json"
	"html/template"
)

// jsStringArray renders items as a JSON array literal suitable for direct
// interpolation into a <script> block via template.JS. Used only for
// operator-configured lists from config.yaml — never for anything derived
// from a request — because template.JS bypasses html/template's escaping.
// JSON string encoding already escapes quotes and backslashes, so the
// result is always a syntactically valid JS array of strings.
func jsStringArray(items []string) (template.JS, error) {
	if items == nil {
		items = []string{}
	}
	b, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return template.JS(b), nil
}
