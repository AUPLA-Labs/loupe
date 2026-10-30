package reputation

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

// snapshotFile is the on-disk shape written by Snapshot and read by Restore.
// Keys are strings even for the ASN map because encoding/json requires
// string map keys for arbitrary integer types to round-trip through a
// human-readable file; ASNSnap re-parses them back to uint on Restore.
type snapshotFile struct {
	IP  map[string]snapshotEntry `json:"ip"`
	ASN map[string]snapshotEntry `json:"asn"`
}

type snapshotEntry struct {
	Value      float64   `json:"value"`
	LastUpdate time.Time `json:"last_update"`
	LastClean  time.Time `json:"last_clean,omitempty"`
}

// Snapshot writes the store's current state to path, atomically (via a
// temp-file-then-rename) so a crash mid-write never leaves a truncated file
// that Restore would fail to parse.
func (s *Store) Snapshot(path string) error {
	s.mu.Lock()
	out := snapshotFile{
		IP:  make(map[string]snapshotEntry, len(s.ip)),
		ASN: make(map[string]snapshotEntry, len(s.asn)),
	}
	for k, e := range s.ip {
		out.IP[k] = snapshotEntry{Value: e.Value, LastUpdate: e.LastUpdate, LastClean: e.LastClean}
	}
	for a, e := range s.asn {
		out.ASN[uintToKey(a)] = snapshotEntry{Value: e.Value, LastUpdate: e.LastUpdate, LastClean: e.LastClean}
	}
	s.mu.Unlock()

	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Restore loads state written by Snapshot. A missing file is not an error —
// it just means this is the first boot, or persistence was only just turned
// on — the store simply starts empty. LastUpdate/LastClean timestamps are
// preserved exactly as written, so the next read's lazy decay
// correctly accounts for however long the process was down.
func (s *Store) Restore(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var in snapshotFile
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range in.IP {
		s.ip[k] = &entry{Value: e.Value, LastUpdate: e.LastUpdate, LastClean: e.LastClean}
	}
	for a, e := range in.ASN {
		asn, err := keyToUint(a)
		if err != nil {
			continue // skip a corrupt/foreign key rather than failing the whole restore
		}
		s.asn[asn] = &entry{Value: e.Value, LastUpdate: e.LastUpdate, LastClean: e.LastClean}
	}
	return nil
}

func uintToKey(a uint) string {
	return strconv.FormatUint(uint64(a), 10)
}

func keyToUint(s string) (uint, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	return uint(v), err
}
