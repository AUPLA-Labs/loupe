package cookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type Manager struct {
	secret []byte
	name   string
	ttl    time.Duration
}

func New(secret, name string, ttlSeconds int) *Manager {
	return &Manager{
		secret: []byte(secret),
		name:   name,
		ttl:    time.Duration(ttlSeconds) * time.Second,
	}
}

// probeCookieName is a short-lived, non-authoritative cookie set alongside
// the pulse interstitial (Handler.servePulse) purely to detect whether this
// client accepts cookies at all. Only its presence is ever
// checked, never a signed value, so unlike the clearance cookie it needs no
// HMAC.
const probeCookieName = "loupe_probe"

// probeCookieTTL is deliberately short: this cookie only needs to survive
// one same-origin POST back to the server that just set it.
const probeCookieTTL = 5 * time.Minute

// IssueProbe sets the probe cookie. Uses the same registrableDomain
// derivation as IssueWithProfile so the Domain attribute matches this
// request's host under multi-domain hosting, same as the clearance cookie.
func (m *Manager) IssueProbe(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     probeCookieName,
		Value:    "1",
		MaxAge:   int(probeCookieTTL.Seconds()),
		Path:     "/",
		Domain:   registrableDomain(r.Host),
		HttpOnly: true,
		Secure:   IsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// HasProbe reports whether the cookie set by IssueProbe came back with this
// request. Absence means this client rejects cookies outright.
func (m *Manager) HasProbe(r *http.Request) bool {
	_, err := r.Cookie(probeCookieName)
	return err == nil
}

// Issue sets a signed cookie with no behavioral profile.
func (m *Manager) Issue(w http.ResponseWriter, ip string, r *http.Request) {
	m.IssueWithProfile(w, ip, r, "")
}

// payloadVersion prefixes every clearance payload. Cookies from before the
// v2 format (no version field) no longer validate, so every client re-runs
// the pulse once to receive one that records its header shape.
const payloadVersion = "2"

// IssueWithProfile sets a signed cookie embedding a behavioral profile hash.
// profileHash may be empty string if no behavioral data was collected.
//
// Payload format, "|"-separated, followed by a 64-char HMAC hex and
// base64url-encoded:
//
//	2|<expiry>|<ip>|<uaFP>|<profileHash>|<id>|<shape>|<flags>
//
// id is a random per-cookie identifier (for per-cookie budgets and
// revocation), shape is ShapeOf(r), and flags records which header families
// the issuing request carried: "f" for Sec-Fetch-*, "c" for Sec-CH-UA.
func (m *Manager) IssueWithProfile(w http.ResponseWriter, ip string, r *http.Request, profileHash string) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	expiry := time.Now().Add(m.ttl).Unix()
	payload := strings.Join([]string{
		payloadVersion,
		strconv.FormatInt(expiry, 10),
		ip,
		uaFingerprint(r.UserAgent()),
		profileHash,
		hex.EncodeToString(idBytes),
		ShapeOf(r),
		headerFlags(r),
	}, "|")
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + m.sign(payload)))
	http.SetCookie(w, &http.Cookie{
		Name:     m.name,
		Value:    value,
		Expires:  time.Unix(expiry, 0),
		Path:     "/",
		Domain:   registrableDomain(r.Host),
		HttpOnly: true,
		Secure:   IsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear expires the clearance cookie on this response, using the same
// Domain derivation as IssueWithProfile so the browser matches it.
func (m *Manager) Clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.name,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   registrableDomain(r.Host),
		HttpOnly: true,
		Secure:   IsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// ShapeOf hashes the request headers a browser sends identically on every
// request for the life of a clearance cookie: the primary Accept-Language
// subtag and the low-entropy UA client hints. A different shape on a later
// request means a different client is using the cookie, or the browser
// updated (Sec-CH-UA changes with the major version).
//
// Only the primary language subtag is used, not the whole header, so
// browsers that vary the q-value list between requests (Chrome's
// Accept-Language reduction) keep a stable shape.
func ShapeOf(r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(PrimaryLanguage(r.Header.Get("Accept-Language"))))
	for _, name := range []string{"Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile"} {
		h.Write([]byte{0})
		h.Write([]byte(r.Header.Get(name)))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// PrimaryLanguage returns the lowercased base subtag of the first entry in
// an Accept-Language-style list: "de-AT,de;q=0.9" → "de".
func PrimaryLanguage(header string) string {
	first := strings.TrimSpace(strings.SplitN(header, ",", 2)[0])
	first = strings.SplitN(first, ";", 2)[0]
	first = strings.SplitN(first, "-", 2)[0]
	return strings.ToLower(strings.TrimSpace(first))
}

func headerFlags(r *http.Request) string {
	f := ""
	if r.Header.Get("Sec-Fetch-Site") != "" {
		f += "f"
	}
	if r.Header.Get("Sec-CH-UA") != "" {
		f += "c"
	}
	return f
}

// IsHTTPS reports whether the visitor reached the site over HTTPS: TLS on
// this connection, or X-Forwarded-Proto saying so (its first value is the
// hop nearest the visitor). By the time Loupe sets a cookie the handler has
// already rewritten that header from proxy.trusted, so a visitor can't
// forge it.
// Cookies are Secure only then; a Secure cookie set over plain HTTP is
// dropped by the browser, and the visitor could never be cleared.
func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// registrableDomain derives the Set-Cookie Domain attribute from the
// request's own Host header, so one Manager can correctly serve multiple
// registrable domains (e.g. example.org and example.net) instead of leaking
// a domain fixed at startup onto responses it doesn't match. A cookie's
// Domain must be host-equal to, or a parent of, the response's own host or
// browsers silently drop it (RFC 6265 §5.3).
//
// Uses the public suffix list so multi-part suffixes (e.g. "co.uk") resolve
// to the correct registrable domain instead of naively taking the last two
// labels, which would compute "co.uk" itself for "example.co.uk". Falls
// back to the raw host for bare IPs, "localhost", or anything else the list
// doesn't recognize as having a registrable domain.
func registrableDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil {
		return host
	}
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return etld1
	}
	return host
}

// Clearance is what a valid clearance cookie records about its issuance.
type Clearance struct {
	ID          string
	Expiry      time.Time
	ProfileHash string
	Shape       string
	HadSecFetch bool // the issuing request carried Sec-Fetch-*
	HadCHUA     bool // the issuing request carried Sec-CH-UA
}

// Issued is when c was issued: its expiry less the lifetime, to the second.
func (m *Manager) Issued(c Clearance) time.Time { return c.Expiry.Add(-m.ttl) }

// Validate checks the cookie. Returns true if valid.
func (m *Manager) Validate(r *http.Request, ip string) bool {
	_, ok := m.Check(r, ip)
	return ok
}

// Check verifies the cookie's signature, expiry, IP and UA binding, and
// returns what it recorded at issuance. Whether the current request is
// consistent with that record is the caller's policy.
func (m *Manager) Check(r *http.Request, ip string) (Clearance, bool) {
	fields, ok := m.unexpired(r, ip)
	if !ok || fields[3] != uaFingerprint(r.UserAgent()) {
		return Clearance{}, false
	}
	expiry, _ := strconv.ParseInt(fields[1], 10, 64)
	return Clearance{
		ID:          fields[5],
		Expiry:      time.Unix(expiry, 0),
		ProfileHash: fields[4],
		Shape:       fields[6],
		HadSecFetch: strings.Contains(fields[7], "f"),
		HadCHUA:     strings.Contains(fields[7], "c"),
	}, true
}

// UAChanged reports a genuine, unexpired clearance for this IP that fails
// only on its User-Agent binding: the browser kept its cookie but now sends
// a different UA, as UA-switcher and randomiser extensions do.
func (m *Manager) UAChanged(r *http.Request, ip string) bool {
	fields, ok := m.unexpired(r, ip)
	return ok && fields[3] != uaFingerprint(r.UserAgent())
}

// unexpired returns the payload fields of a correctly signed, current-version,
// unexpired clearance cookie issued to ip, without checking the UA binding.
func (m *Manager) unexpired(r *http.Request, ip string) ([]string, bool) {
	c, err := r.Cookie(m.name)
	if err != nil {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, false
	}
	s := string(raw)
	if len(s) <= 64 {
		return nil, false
	}
	payload, sig := s[:len(s)-64], s[len(s)-64:]
	if !hmac.Equal([]byte(m.sign(payload)), []byte(sig)) {
		return nil, false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 8 || fields[0] != payloadVersion {
		return nil, false
	}
	expiry, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() >= expiry || fields[2] != ip {
		return nil, false
	}
	return fields, true
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func uaFingerprint(ua string) string {
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:])[:16]
}

// ProfileHash computes a short behavioral profile hash from signal buckets.
// The result is an HMAC so it cannot be forged without the server secret.
func ProfileHash(secret []byte, jitter, rafVariance float64, webglRenderer string, scrollObserved bool) string {
	jitterBucket := "H"
	if jitter < 2.0 {
		jitterBucket = "L"
	} else if jitter < 50.0 {
		jitterBucket = "M"
	}

	rafBucket := "N"
	if rafVariance >= 0 && rafVariance < 0.5 {
		rafBucket = "U"
	}

	webglShort := "x"
	if webglRenderer != "" {
		h := sha256.Sum256([]byte(webglRenderer))
		webglShort = hex.EncodeToString(h[:])[:8]
	}

	scrollBit := "0"
	if scrollObserved {
		scrollBit = "1"
	}

	msg := jitterBucket + "|" + rafBucket + "|" + webglShort + "|" + scrollBit
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// ProfileDrifted returns true when the stored and current profile hashes differ.
// Returns false when either hash is empty (no profile data available).
// The probe-result handler uses it to trigger a silent re-challenge on drift.
func ProfileDrifted(stored, current string) bool {
	if stored == "" || current == "" {
		return false
	}
	return stored != current
}
