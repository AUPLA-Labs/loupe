// Package aupldb reads .aupldb files, AUPLA's IP database: per address the
// origin ASN, AS name and type, location country and RIR registration, as
// flat sorted ranges with a binary search per lookup, signed with Ed25519.
// The layout is specified in auplalabs-api's aupldb/FORMAT.md (version 3).
// It also has the Overlay, for lists that change faster than the file. Keep
// in step with auplalabs-api/aupldb, which this mirrors.
package aupldb

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"math"
	"net/netip"
	"os"
	"sort"
	"time"
)

const (
	Magic   = "AUPLDB"
	Version = 3

	headerSize   = 64
	dirEntrySize = 24
	footerSize   = sha256.Size + ed25519.SignatureSize
	recSize      = 16
	asSize       = 12
	noName       = 0xFFFFFFFF
	notRouted    = 0xFFFFFFFF
	groupBit     = 1 << 31
	flagCritical = 1 << 0
)

// The sections version 3 defines, in the order Write emits them, with their
// element sizes.
var sections = []struct {
	tag  string
	size int
}{
	{"V4KY", 4}, {"V4RF", 4}, {"V6KY", 8}, {"V6RF", 4}, {"V6GR", 4}, {"V6FK", 8}, {"V6FR", 4},
	{"RECS", recSize}, {"ASES", asSize}, {"STRS", 1}, {"META", 1},
}

// Record is what an address maps to. Name, Category and Role belong to the
// AS, so every record with the same ASN has the same ones.
type Record struct {
	ASN               uint32 // 0 = not routed
	Name              string // AS (organisation) name, or ""
	Category          Category
	Role              Role
	Country           string // ISO 3166 alpha-2 where the address is used, or ""
	RegisteredCountry string // ISO 3166 alpha-2 from the RIR registration, or ""
	RIR               RIR
	Flags             uint8
	Allocated         uint32 // YYYYMMDD, or 0
}

func (r Record) Routed() bool { return r.ASN != 0 }
func (r Record) MOAS() bool   { return r.Flags&FlagMOAS != 0 }

// AS is one entry of the AS table: every AS that originates a range.
type AS struct {
	ASN      uint32
	Name     string // or ""
	Category Category
	Role     Role
}

// Range is an inclusive span of addresses that share one record.
type Range struct {
	Start, End netip.Addr
}

// DB is a parsed, validated file. It is immutable and safe for concurrent use.
type DB struct {
	BuiltAt time.Time
	SHA256  string
	Sources json.RawMessage
	Version int
	KeyID   [8]byte // all zero for an unsigned file

	v4k, v4r, v6k, v6r, v6g, v6fk, v6fr, recs, ases, strs []byte

	nV4, nV6, nFine, nGroups, nRec, nAS int
	nV6Ranges                           int      // after joining pieces
	v4idx                               []uint32 // v4idx[h]: first V4KY entry ≥ h<<16, for h in 0..65536
	body, sig                           []byte
	size                                int
}

var (
	ErrUnsigned     = errors.New("aupldb: file is not signed")
	ErrUnknownKey   = errors.New("aupldb: file is signed by a key that isn't trusted")
	ErrBadSignature = errors.New("aupldb: bad signature")
)

func Open(path string) (*DB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func align8(n uint64) uint64 { return (n + 7) &^ 7 }

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Parse validates data completely (see the reader checklist in FORMAT.md),
// so lookups afterwards need no bounds checks. It checks the SHA-256 but not
// the signature, which needs keys: see Verify. data must not be modified
// while the DB is in use.
func Parse(data []byte) (*DB, error) {
	if len(data) < headerSize+footerSize {
		return nil, errors.New("aupldb: file too short")
	}
	if string(data[:6]) != Magic {
		return nil, errors.New("aupldb: bad magic")
	}
	le := binary.LittleEndian
	if v := le.Uint16(data[6:]); v != Version {
		return nil, fmt.Errorf("aupldb: unsupported version %d", v)
	}
	size := uint64(len(data))
	nSec := uint64(le.Uint32(data[12:]))
	dirEnd := headerSize + nSec*dirEntrySize
	if nSec == 0 || dirEnd > size-footerSize {
		return nil, errors.New("aupldb: bad section count")
	}
	secs := map[string][]byte{}
	off, prevEnd := align8(dirEnd), dirEnd
	for i := range nSec {
		e := data[headerSize+i*dirEntrySize:]
		tag, flags := string(e[:4]), le.Uint32(e[4:])
		o, n := le.Uint64(e[8:]), le.Uint64(e[16:])
		if o != off || o > size || n > size-o {
			return nil, fmt.Errorf("aupldb: section %q is out of place", tag)
		}
		if !allZero(data[prevEnd:o]) {
			return nil, fmt.Errorf("aupldb: padding before section %q isn't zero", tag)
		}
		if _, dup := secs[tag]; dup {
			return nil, fmt.Errorf("aupldb: section %q appears twice", tag)
		}
		if !knownSection(tag) && flags&flagCritical != 0 {
			return nil, fmt.Errorf("aupldb: unknown critical section %q", tag)
		}
		secs[tag] = data[o : o+n]
		prevEnd, off = o+n, align8(o+n)
	}
	if off > size || size-off != footerSize || !allZero(data[prevEnd:off]) {
		return nil, fmt.Errorf("aupldb: size is %d bytes, sections imply %d", size, off+footerSize)
	}

	body := data[:off]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], data[off:off+sha256.Size]) {
		return nil, errors.New("aupldb: checksum mismatch")
	}
	db := &DB{
		Version: Version,
		BuiltAt: time.Unix(int64(le.Uint64(data[16:])), 0).UTC(),
		SHA256:  hex.EncodeToString(sum[:]),
		KeyID:   [8]byte(data[24:32]),
		body:    body,
		sig:     data[off+sha256.Size:],
		size:    len(data),
	}
	if allZero(db.KeyID[:]) != allZero(db.sig) {
		return nil, errors.New("aupldb: key ID and signature must both be set or both be zero")
	}

	for _, s := range sections {
		b, ok := secs[s.tag]
		if !ok {
			return nil, fmt.Errorf("aupldb: section %q is missing", s.tag)
		}
		if len(b)%s.size != 0 {
			return nil, fmt.Errorf("aupldb: section %q isn't a whole number of entries", s.tag)
		}
	}
	db.v4k, db.v4r, db.v6k, db.v6r = secs["V4KY"], secs["V4RF"], secs["V6KY"], secs["V6RF"]
	db.v6g, db.v6fk, db.v6fr = secs["V6GR"], secs["V6FK"], secs["V6FR"]
	db.recs, db.ases, db.strs = secs["RECS"], secs["ASES"], secs["STRS"]
	db.Sources = json.RawMessage(secs["META"])
	db.nV4, db.nV6, db.nFine = len(db.v4k)/4, len(db.v6k)/8, len(db.v6fk)/8
	db.nGroups, db.nRec, db.nAS = len(db.v6g)/4-1, len(db.recs)/recSize, len(db.ases)/asSize
	if len(db.v4r)/4 != db.nV4 || len(db.v6r)/4 != db.nV6 || len(db.v6fr)/4 != db.nFine {
		return nil, errors.New("aupldb: key and record tables differ in length")
	}
	if db.nV4 == 0 || db.nV6 == 0 || db.nRec == 0 || db.nGroups < 0 {
		return nil, errors.New("aupldb: empty table")
	}
	if err := db.check(); err != nil {
		return nil, err
	}
	if !json.Valid(db.Sources) {
		return nil, errors.New("aupldb: meta section is not valid JSON")
	}
	db.buildV4Index()
	for p, ok := db.v6First(0), true; ok; p, ok = db.v6Next(p) {
		if q, ok := db.v6Prev(p); !ok || db.v6Rec(q) != db.v6Rec(p) {
			db.nV6Ranges++
		}
	}
	return db, nil
}

func knownSection(tag string) bool {
	for _, s := range sections {
		if s.tag == tag {
			return true
		}
	}
	return false
}

// check covers the reader checklist from the range tables on.
func (db *DB) check() error {
	for i := range db.nV4 {
		if i == 0 && db.v4Key(0) != 0 || i > 0 && db.v4Key(i) <= db.v4Key(i-1) {
			return fmt.Errorf("aupldb: v4 entry %d out of order", i)
		}
		if int(db.v4Rec(i)) >= db.nRec {
			return fmt.Errorf("aupldb: v4 entry %d points past the record table", i)
		}
	}
	if db.v6Group(0) != 0 || db.v6Group(db.nGroups) != uint32(db.nFine) {
		return errors.New("aupldb: v6 group table doesn't span the fine table")
	}
	seen := make([]bool, db.nGroups)
	for i := range db.nV6 {
		key, ref := db.v6Key(i), db.v6Ref(i)
		if i == 0 && key != 0 || i > 0 && key <= db.v6Key(i-1) {
			return fmt.Errorf("aupldb: v6 entry %d out of order", i)
		}
		if ref&groupBit == 0 {
			if int(ref) >= db.nRec {
				return fmt.Errorf("aupldb: v6 entry %d points past the record table", i)
			}
			continue
		}
		g := int(ref &^ groupBit)
		if g >= db.nGroups || seen[g] {
			return fmt.Errorf("aupldb: v6 entry %d has a bad or reused group", i)
		}
		seen[g] = true
		if i+1 < db.nV6 && db.v6Key(i+1) != key+1 || i+1 == db.nV6 && key != math.MaxUint64 {
			return fmt.Errorf("aupldb: v6 entry %d is a group but covers more than one /64", i)
		}
		lo, hi := db.v6Group(g), db.v6Group(g+1)
		if hi <= lo || hi > uint32(db.nFine) {
			return fmt.Errorf("aupldb: v6 group %d is empty or out of bounds", g)
		}
		for j := lo; j < hi; j++ {
			if j == lo && db.v6FineKey(int(j)) != 0 || j > lo && db.v6FineKey(int(j)) <= db.v6FineKey(int(j-1)) {
				return fmt.Errorf("aupldb: v6 group %d out of order", g)
			}
			if int(db.v6FineRec(int(j))) >= db.nRec {
				return fmt.Errorf("aupldb: v6 group %d points past the record table", g)
			}
		}
	}
	for g := range db.nGroups {
		if !seen[g] || db.v6Group(g+1) < db.v6Group(g) {
			return fmt.Errorf("aupldb: v6 group %d is unused or out of order", g)
		}
	}
	le := binary.LittleEndian
	for i := range db.nRec {
		if as := le.Uint32(db.recs[i*recSize:]); as != notRouted && int(as) >= db.nAS {
			return fmt.Errorf("aupldb: record %d points past the AS table", i)
		}
	}
	strLen := uint64(len(db.strs))
	for i := range db.nAS {
		e := db.ases[i*asSize:]
		if asn := le.Uint32(e); asn == 0 || i > 0 && asn <= le.Uint32(db.ases[(i-1)*asSize:]) {
			return fmt.Errorf("aupldb: AS entry %d out of order", i)
		}
		name := le.Uint32(e[4:])
		if name == noName {
			continue
		}
		if uint64(name)+2 > strLen || uint64(name)+2+uint64(le.Uint16(db.strs[name:])) > strLen {
			return fmt.Errorf("aupldb: AS entry %d name points outside the string table", i)
		}
	}
	return nil
}

func (db *DB) buildV4Index() {
	db.v4idx = make([]uint32, 1<<16+1)
	j := 0
	for h := range uint64(1<<16 + 1) {
		for j < db.nV4 && uint64(db.v4Key(j)) < h<<16 {
			j++
		}
		db.v4idx[h] = uint32(j)
	}
}

func (db *DB) V4Ranges() int { return db.nV4 }
func (db *DB) V6Ranges() int { return db.nV6Ranges }
func (db *DB) Records() int  { return db.nRec }
func (db *DB) ASes() int     { return db.nAS }
func (db *DB) Size() int     { return db.size }

// Signed reports whether the file carries a signature. Only Verify says
// whether it is a good one.
func (db *DB) Signed() bool { return !allZero(db.KeyID[:]) }

// Verify checks the signature against the trusted keys: it returns nil if
// the key the file names is among them and its signature is good.
func (db *DB) Verify(keys []ed25519.PublicKey) error {
	if !db.Signed() {
		return ErrUnsigned
	}
	for _, k := range keys {
		if KeyID(k) == db.KeyID {
			if !ed25519.Verify(k, db.body, db.sig) {
				return ErrBadSignature
			}
			return nil
		}
	}
	return ErrUnknownKey
}

func (db *DB) v4Key(i int) uint32     { return binary.LittleEndian.Uint32(db.v4k[i*4:]) }
func (db *DB) v4Rec(i int) uint32     { return binary.LittleEndian.Uint32(db.v4r[i*4:]) }
func (db *DB) v6Key(i int) uint64     { return binary.LittleEndian.Uint64(db.v6k[i*8:]) }
func (db *DB) v6Ref(i int) uint32     { return binary.LittleEndian.Uint32(db.v6r[i*4:]) }
func (db *DB) v6Group(g int) uint32   { return binary.LittleEndian.Uint32(db.v6g[g*4:]) }
func (db *DB) v6FineKey(j int) uint64 { return binary.LittleEndian.Uint64(db.v6fk[j*8:]) }
func (db *DB) v6FineRec(j int) uint32 { return binary.LittleEndian.Uint32(db.v6fr[j*4:]) }

func (db *DB) as(i uint32) AS {
	e := db.ases[int(i)*asSize:]
	le := binary.LittleEndian
	a := AS{ASN: le.Uint32(e), Category: Category(e[8]), Role: Role(e[9])}
	if off := le.Uint32(e[4:]); off != noName {
		n := uint32(le.Uint16(db.strs[off:]))
		a.Name = string(db.strs[off+2 : off+2+n])
	}
	return a
}

func (db *DB) record(i uint32) Record {
	e := db.recs[int(i)*recSize:]
	le := binary.LittleEndian
	r := Record{RIR: RIR(e[6]), Flags: e[7], Allocated: le.Uint32(e[8:])}
	if as := le.Uint32(e); as != notRouted {
		a := db.as(as)
		r.ASN, r.Name, r.Category, r.Role = a.ASN, a.Name, a.Category, a.Role
	}
	if e[4] != 0 {
		r.RegisteredCountry = string(e[4:6])
	}
	if e[12] != 0 {
		r.Country = string(e[12:14])
	}
	return r
}

// LookupASN returns the AS table entry for asn, if any range is originated
// by it.
func (db *DB) LookupASN(asn uint32) (AS, bool) {
	i := sort.Search(db.nAS, func(i int) bool { return binary.LittleEndian.Uint32(db.ases[i*asSize:]) >= asn })
	if i == db.nAS || binary.LittleEndian.Uint32(db.ases[i*asSize:]) != asn {
		return AS{}, false
	}
	return db.as(uint32(i)), true
}

var (
	maxV4 = netip.MustParseAddr("255.255.255.255")
	maxV6 = netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
)

func addr4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func addr6(hi, lo uint64) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}

func (db *DB) v4Range(i int) (Range, Record) {
	end := maxV4
	if i+1 < db.nV4 {
		end = addr4(db.v4Key(i+1) - 1)
	}
	return Range{addr4(db.v4Key(i)), end}, db.record(db.v4Rec(i))
}

// A v6Piece is one stored IPv6 range: coarse entry i, or fine entry j of the
// group in coarse entry i (j = -1 when i isn't a group). A range that
// crosses a group boundary is stored as two or more pieces with the same
// record, which Lookup and All join up again.
type v6Piece struct{ i, j int }

// v6GroupSpan is the span of fine entries of coarse entry i, which must be a
// group.
func (db *DB) v6GroupSpan(i int) (first, end int) {
	g := int(db.v6Ref(i) &^ groupBit)
	return int(db.v6Group(g)), int(db.v6Group(g + 1))
}

func (db *DB) v6First(i int) v6Piece {
	if db.v6Ref(i)&groupBit == 0 {
		return v6Piece{i, -1}
	}
	first, _ := db.v6GroupSpan(i)
	return v6Piece{i, first}
}

func (db *DB) v6Last(i int) v6Piece {
	if db.v6Ref(i)&groupBit == 0 {
		return v6Piece{i, -1}
	}
	_, end := db.v6GroupSpan(i)
	return v6Piece{i, end - 1}
}

func (db *DB) v6Next(p v6Piece) (v6Piece, bool) {
	if p.j >= 0 {
		if _, end := db.v6GroupSpan(p.i); p.j+1 < end {
			return v6Piece{p.i, p.j + 1}, true
		}
	}
	if p.i+1 == db.nV6 {
		return p, false
	}
	return db.v6First(p.i + 1), true
}

func (db *DB) v6Prev(p v6Piece) (v6Piece, bool) {
	if p.j >= 0 {
		if first, _ := db.v6GroupSpan(p.i); p.j > first {
			return v6Piece{p.i, p.j - 1}, true
		}
	}
	if p.i == 0 {
		return p, false
	}
	return db.v6Last(p.i - 1), true
}

func (db *DB) v6Rec(p v6Piece) uint32 {
	if p.j < 0 {
		return db.v6Ref(p.i)
	}
	return db.v6FineRec(p.j)
}

func (db *DB) v6Start(p v6Piece) netip.Addr {
	if p.j < 0 {
		return addr6(db.v6Key(p.i), 0)
	}
	return addr6(db.v6Key(p.i), db.v6FineKey(p.j))
}

func (db *DB) v6End(p v6Piece) netip.Addr {
	if next, ok := db.v6Next(p); ok {
		return db.v6Start(next).Prev()
	}
	return maxV6
}

// v6Range joins p with the pieces around it that have the same record. It
// returns the last piece of the range, for All.
func (db *DB) v6Range(p v6Piece) (Range, Record, v6Piece) {
	rec := db.v6Rec(p)
	first, last := p, p
	for q, ok := db.v6Prev(first); ok && db.v6Rec(q) == rec; q, ok = db.v6Prev(q) {
		first = q
	}
	for q, ok := db.v6Next(last); ok && db.v6Rec(q) == rec; q, ok = db.v6Next(q) {
		last = q
	}
	return Range{db.v6Start(first), db.v6End(last)}, db.record(rec), last
}

// Lookup returns the record for ip and the range it belongs to. Every
// address is covered, so it only fails for an invalid Addr.
func (db *DB) Lookup(ip netip.Addr) (Record, Range, bool) {
	if !ip.IsValid() {
		return Record{}, Range{}, false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		key := binary.BigEndian.Uint32(b[:])
		lo, hi := int(db.v4idx[key>>16]), int(db.v4idx[key>>16+1])
		i := lo + sort.Search(hi-lo, func(k int) bool { return db.v4Key(lo+k) > key }) - 1
		rg, rec := db.v4Range(i)
		return rec, rg, true
	}
	b := ip.As16()
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	i := sort.Search(db.nV6, func(i int) bool { return db.v6Key(i) > hi }) - 1
	p := v6Piece{i, -1}
	if db.v6Ref(i)&groupBit != 0 {
		first, end := db.v6GroupSpan(i)
		p.j = first + sort.Search(end-first, func(k int) bool { return db.v6FineKey(first+k) > lo }) - 1
	}
	rg, rec, _ := db.v6Range(p)
	return rec, rg, true
}

// All yields every range in address order, IPv4 first.
func (db *DB) All() iter.Seq2[Range, Record] {
	return func(yield func(Range, Record) bool) {
		for i := range db.nV4 {
			if !yield(db.v4Range(i)) {
				return
			}
		}
		for p, ok := db.v6First(0), true; ok; p, ok = db.v6Next(p) {
			rg, rec, last := db.v6Range(p)
			if !yield(rg, rec) {
				return
			}
			p = last
		}
	}
}

// AllASes yields the AS table in ASN order.
func (db *DB) AllASes() iter.Seq[AS] {
	return func(yield func(AS) bool) {
		for i := range db.nAS {
			if !yield(db.as(uint32(i))) {
				return
			}
		}
	}
}
