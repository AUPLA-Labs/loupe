package main

import (
	_ "embed"
	"strings"
)

// exampleConfigTmpl is config.example.yaml (the repo root links to it), the
// config `loupe install` writes.
//
//go:embed config.example.yaml
var exampleConfigTmpl string

// exampleConfig fills in the example config's three placeholders.
func exampleConfig(backend, listen, adminListen string) []byte {
	return []byte(strings.NewReplacer(
		"{{BACKEND}}", backend,
		"{{LISTEN}}", listen,
		"{{ADMIN_LISTEN}}", adminListen,
	).Replace(exampleConfigTmpl))
}
