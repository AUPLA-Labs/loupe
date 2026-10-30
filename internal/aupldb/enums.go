package aupldb

// RIR is the regional registry a block was delegated by.
type RIR uint8

const (
	RIRNone RIR = iota
	RIRARIN
	RIRRIPE
	RIRAPNIC
	RIRLACNIC
	RIRAFRINIC
)

var rirNames = [...]string{"", "arin", "ripencc", "apnic", "lacnic", "afrinic"}

// String returns the registry's name as it appears in the RIR stats files,
// "" for RIRNone and "unknown" for values this version doesn't know.
func (r RIR) String() string { return enumString(rirNames[:], uint8(r)) }

// ParseRIR is the inverse of String.
func ParseRIR(s string) (RIR, bool) {
	i, ok := enumParse(rirNames[:], s)
	return RIR(i), ok
}

// Category is what kind of organisation operates an AS (from ipverse).
type Category uint8

const (
	CategoryUnknown Category = iota
	CategoryISP
	CategoryBusiness
	CategoryHosting
	CategoryEducation
	CategoryGovernment
)

var categoryNames = [...]string{"", "isp", "business", "hosting", "education_research", "government_admin"}

// String returns the category's name, "" for CategoryUnknown and "unknown"
// for values this version doesn't know.
func (c Category) String() string { return enumString(categoryNames[:], uint8(c)) }

// ParseCategory is the inverse of String.
func ParseCategory(s string) (Category, bool) {
	i, ok := enumParse(categoryNames[:], s)
	return Category(i), ok
}

// Role is an AS's place in the routing hierarchy (from ipverse).
type Role uint8

const (
	RoleUnknown Role = iota
	RoleStub
	RoleAccessProvider
	RoleContentNetwork
	RoleMidsizeTransit
	RoleMajorTransit
	RoleTier1Transit
)

var roleNames = [...]string{"", "stub", "access_provider", "content_network", "midsize_transit", "major_transit", "tier1_transit"}

func (r Role) String() string { return enumString(roleNames[:], uint8(r)) }

// ParseRole is the inverse of String.
func ParseRole(s string) (Role, bool) {
	i, ok := enumParse(roleNames[:], s)
	return Role(i), ok
}

func enumString(names []string, v uint8) string {
	if int(v) < len(names) {
		return names[v]
	}
	return "unknown"
}

func enumParse(names []string, s string) (uint8, bool) {
	for i, n := range names {
		if n == s && i > 0 {
			return uint8(i), true
		}
	}
	return 0, false
}

// FlagMOAS marks a range whose prefix was announced by more than one origin
// AS; ASN is then the origin seen by the most peers.
const FlagMOAS = 1 << 0
