package aupldb

import (
	"bytes"
	"crypto/ed25519"
	"time"
)

// TestKey signs the files Build makes, and TestPublicKeys trusts it. Only
// for tests: the private key is public.
var (
	TestKey        = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	TestPublicKeys = []ed25519.PublicKey{TestKey.Public().(ed25519.PublicKey)}
)

// Build encodes a file signed with TestKey, for tests. v4 and v6 must each
// be sorted by Start and begin at 0.0.0.0 / ::; sources must be valid JSON.
func Build(builtAt time.Time, v4, v6 []Entry, sources string) []byte {
	var buf bytes.Buffer
	f := &File{BuiltAt: builtAt, V4: v4, V6: v6, Sources: rawJSON(sources), Key: TestKey}
	if err := Write(&buf, f); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// rawJSON marshals as itself.
type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }
