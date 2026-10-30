package aupldb

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Entry starts a range: it covers Start up to the next entry's Start.
type Entry struct {
	Start  netip.Addr
	Record Record
}

// File is everything a .aupldb file holds, in writer-friendly form.
type File struct {
	BuiltAt time.Time
	V4, V6  []Entry            // sorted by Start; each must begin at 0.0.0.0 / ::
	Sources any                // marshalled to JSON
	Key     ed25519.PrivateKey // signs the file; nil writes it unsigned
}

type recKey struct {
	as    uint32
	regCC [2]byte
	rir   RIR
	flags uint8
	alloc uint32
	cc    [2]byte
}

func countryCode(cc string) ([2]byte, error) {
	switch len(cc) {
	case 0:
		return [2]byte{}, nil
	case 2:
		return [2]byte{cc[0], cc[1]}, nil
	}
	return [2]byte{}, fmt.Errorf("aupldb: country %q is not two letters", cc)
}

// Write encodes f. Adjacent entries with identical records are merged and
// records, ASes and names are deduplicated, so callers needn't do any of
// that. The same File always encodes to the same bytes.
func Write(w io.Writer, f *File) error {
	src, err := json.Marshal(f.Sources)
	if err != nil {
		return fmt.Errorf("aupldb: sources: %w", err)
	}
	for fam, entries := range [][]Entry{f.V4, f.V6} {
		if err := checkEntries(entries, fam == 0); err != nil {
			return err
		}
	}
	le := binary.LittleEndian

	// The AS table first: records point into it, and it is sorted by ASN.
	asInfo := map[uint32]AS{}
	for e := range concat(f.V4, f.V6) {
		r := e.Record
		a := AS{r.ASN, r.Name, r.Category, r.Role}
		if r.ASN == 0 {
			if a != (AS{}) {
				return errors.New("aupldb: an unrouted record has an AS name, category or role")
			}
			continue
		}
		if len(r.Name) > 0xFFFF {
			return fmt.Errorf("aupldb: name for AS%d is too long", r.ASN)
		}
		if prev, ok := asInfo[r.ASN]; ok && prev != a {
			return fmt.Errorf("aupldb: AS%d has different names or types in different records", r.ASN)
		}
		asInfo[r.ASN] = a
	}
	asns := slices.Sorted(func(yield func(uint32) bool) {
		for asn := range asInfo {
			if !yield(asn) {
				return
			}
		}
	})
	var (
		strs   []byte
		strIdx = map[string]uint32{}
		ases   []byte
		asIdx  = make(map[uint32]uint32, len(asns))
	)
	for i, asn := range asns {
		a := asInfo[asn]
		asIdx[asn] = uint32(i)
		off := uint32(noName)
		if a.Name != "" {
			var ok bool
			if off, ok = strIdx[a.Name]; !ok {
				off = uint32(len(strs))
				strIdx[a.Name] = off
				strs = le.AppendUint16(strs, uint16(len(a.Name)))
				strs = append(strs, a.Name...)
			}
		}
		ases = le.AppendUint32(ases, asn)
		ases = le.AppendUint32(ases, off)
		ases = append(ases, byte(a.Category), byte(a.Role), 0, 0)
	}

	var (
		recs   []byte
		recIdx = map[recKey]uint32{}
	)
	intern := func(r Record) (uint32, error) {
		k := recKey{as: notRouted, rir: r.RIR, flags: r.Flags, alloc: r.Allocated}
		if r.ASN != 0 {
			k.as = asIdx[r.ASN]
		}
		var err error
		if k.regCC, err = countryCode(r.RegisteredCountry); err != nil {
			return 0, err
		}
		if k.cc, err = countryCode(r.Country); err != nil {
			return 0, err
		}
		i, ok := recIdx[k]
		if !ok {
			i = uint32(len(recs) / recSize)
			recIdx[k] = i
			recs = le.AppendUint32(recs, k.as)
			recs = append(recs, k.regCC[0], k.regCC[1], byte(k.rir), k.flags)
			recs = le.AppendUint32(recs, k.alloc)
			recs = append(recs, k.cc[0], k.cc[1], 0, 0)
		}
		return i, nil
	}
	// merged interns entries' records and drops entries whose record is the
	// same as the one before.
	type point struct {
		hi, lo uint64 // for IPv4, the address is lo
		rec    uint32
	}
	merged := func(entries []Entry) ([]point, error) {
		var out []point
		for _, e := range entries {
			ri, err := intern(e.Record)
			if err != nil {
				return nil, err
			}
			if len(out) > 0 && out[len(out)-1].rec == ri {
				continue
			}
			var p point
			if e.Start.Is4() {
				b := e.Start.As4()
				p.lo = uint64(binary.BigEndian.Uint32(b[:]))
			} else {
				b := e.Start.As16()
				p.hi, p.lo = binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
			}
			p.rec = ri
			out = append(out, p)
		}
		return out, nil
	}

	v4, err := merged(f.V4)
	if err != nil {
		return err
	}
	var v4k, v4r []byte
	for _, p := range v4 {
		v4k = le.AppendUint32(v4k, uint32(p.lo))
		v4r = le.AppendUint32(v4r, p.rec)
	}

	// IPv6: a /64 with a range start inside it becomes a group, and the
	// coarse entry for the /64 after it is added if it isn't there already.
	v6, err := merged(f.V6)
	if err != nil {
		return err
	}
	var v6k, v6r, v6g, v6fk, v6fr []byte
	v6g = le.AppendUint32(v6g, 0)
	nFine := uint32(0)
	fine := func(lo uint64, rec uint32) {
		v6fk = le.AppendUint64(v6fk, lo)
		v6fr = le.AppendUint32(v6fr, rec)
		nFine++
	}
	coarse := func(hi uint64, ref uint32) {
		v6k = le.AppendUint64(v6k, hi)
		v6r = le.AppendUint32(v6r, ref)
	}
	groups := uint32(0)
	for i := 0; i < len(v6); {
		hi, j := v6[i].hi, i
		for j < len(v6) && v6[j].hi == hi {
			j++
		}
		if j == i+1 && v6[i].lo == 0 {
			coarse(hi, v6[i].rec)
			i = j
			continue
		}
		if v6[i].lo != 0 { // the /64 starts inside the previous range
			fine(0, v6[i-1].rec)
		}
		for _, p := range v6[i:j] {
			fine(p.lo, p.rec)
		}
		coarse(hi, groupBit|groups)
		groups++
		v6g = le.AppendUint32(v6g, nFine)
		if hi != math.MaxUint64 && (j == len(v6) || v6[j].hi != hi+1) {
			coarse(hi+1, v6[j-1].rec)
		}
		i = j
	}

	body := encodeSections(f.BuiltAt, [][]byte{v4k, v4r, v6k, v6r, v6g, v6fk, v6fr, recs, ases, strs, src}, f.Key)
	sum := sha256.Sum256(body)
	sig := make([]byte, ed25519.SignatureSize)
	if f.Key != nil {
		sig = ed25519.Sign(f.Key, body)
	}
	for _, b := range [][]byte{body, sum[:], sig} {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

func concat(a, b []Entry) iter.Seq[Entry] {
	return func(yield func(Entry) bool) {
		for _, s := range [][]Entry{a, b} {
			for _, e := range s {
				if !yield(e) {
					return
				}
			}
		}
	}
}

func checkEntries(entries []Entry, is4 bool) error {
	if len(entries) == 0 {
		return errors.New("aupldb: empty range table")
	}
	for i, e := range entries {
		if e.Start.Is4() != is4 || e.Start.Is4In6() {
			return fmt.Errorf("aupldb: %s in the wrong table", e.Start)
		}
		if i == 0 && e.Start != netip.IPv4Unspecified() && e.Start != netip.IPv6Unspecified() {
			return fmt.Errorf("aupldb: table starts at %s, not the zero address", e.Start)
		}
		if i > 0 && !entries[i-1].Start.Less(e.Start) {
			return fmt.Errorf("aupldb: %s does not come after %s", e.Start, entries[i-1].Start)
		}
	}
	return nil
}

// encodeSections lays out the header, the directory and data (one []byte
// per entry of sections, in order), and returns the body: everything the
// footer covers.
func encodeSections(builtAt time.Time, data [][]byte, key ed25519.PrivateKey) []byte {
	le := binary.LittleEndian
	n := uint64(len(data))
	off := align8(headerSize + n*dirEntrySize)
	dir := make([]byte, 0, n*dirEntrySize)
	total := off
	for i, d := range data {
		dir = append(dir, sections[i].tag...)
		dir = le.AppendUint32(dir, 0)
		dir = le.AppendUint64(dir, total)
		dir = le.AppendUint64(dir, uint64(len(d)))
		total = align8(total + uint64(len(d)))
	}
	body := make([]byte, total)
	copy(body, Magic)
	le.PutUint16(body[6:], Version)
	le.PutUint32(body[12:], uint32(n))
	le.PutUint64(body[16:], uint64(builtAt.Unix()))
	if key != nil {
		id := KeyID(key.Public().(ed25519.PublicKey))
		copy(body[24:], id[:])
	}
	copy(body[headerSize:], dir)
	for _, d := range data {
		copy(body[off:], d)
		off = align8(off + uint64(len(d)))
	}
	return body
}

// WriteFile writes f to path atomically: readers see either the old file or
// the complete new one, never a partial write.
func WriteFile(path string, f *File) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aupldb-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := Write(tmp, f); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
