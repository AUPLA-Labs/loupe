package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

// Short-lived client cluster keys, comparable to Turnstile's Ephemeral IDs.
// Both keys are HMACs over the fingerprint's component hashes under a salt
// that rotates every clusterKeyEpoch, so keys from different epochs cannot be
// linked. They feed reputation pressure alongside the IP and ASN, and only
// ever raise the challenge tier.

const (
	clusterKeyEpoch = 72 * time.Hour

	// clusterWindow is how long observations count towards the rotation and
	// churn rules.
	clusterWindow = time.Hour
	// A device key seen from this many distinct client keys, or ASNs, within
	// clusterWindow is rotating through proxies.
	rotationIPs  = 5
	rotationASNs = 3
	// One client key producing this many distinct device keys of the same
	// build within clusterWindow is an anti-detect browser randomising its
	// fingerprint per session.
	churnDevices = 4
)

// Device-key inputs, chosen from observed stability:
// surfaces that stayed identical across separate visits of the same
// browser. Media and voices depend on async timing; intl and nav were seen
// to change between visits. Brave re-farbles canvas, audio, WebGL
// parameters, screen and navigator per page load, and Safari's
// fingerprinting protection may add noise to canvas and audio, so both use
// the subset that stays put.
var (
	deviceInputsDefault = []string{"canvas", "audio", "webgl", "webgl_render", "fonts", "screen", "engine"}
	deviceInputsSafari  = []string{"webgl", "webgl_render", "fonts", "screen", "engine"}
	deviceInputsBrave   = []string{"webgl_render", "engine", "fonts"}
)

// clusterKeys derives the device and build keys for a fingerprint's
// component hashes. A key is "" when any of its inputs is missing: a
// partial key would be a different key, so it is better to have none.
func clusterKeys(secret string, now time.Time, hashes map[string]string, c uaClaims, brave bool) (device, build string) {
	if hashes == nil {
		return "", ""
	}
	epoch := strconv.FormatInt(now.Unix()/int64(clusterKeyEpoch/time.Second), 10)

	inputs := deviceInputsDefault
	switch {
	case brave:
		inputs = deviceInputsBrave
	case c.isSafari || c.os == "ios":
		inputs = deviceInputsSafari
	}
	parts := make([]string, 0, len(inputs))
	for _, k := range inputs {
		v := hashes[k]
		if v == "" {
			parts = nil
			break
		}
		parts = append(parts, k+"="+v)
	}
	if parts != nil {
		device = keyMAC(secret, "device|"+epoch+"|"+strings.Join(parts, "|"))
	}

	if hashes["engine"] != "" && hashes["features"] != "" && hashes["webgl_render"] != "" {
		major := c.chromiumMajor
		switch {
		case c.os == "ios":
			major = c.iosMajor
		case c.isFirefox:
			major = c.firefoxMajor
		case c.isSafari:
			major = c.safariMajor
		}
		build = keyMAC(secret, "build|"+epoch+"|"+c.os+"|"+claimedEngine(c)+"|"+strconv.Itoa(major)+
			"|"+hashes["engine"]+"|"+hashes["features"]+"|"+hashes["webgl_render"])
	}
	return device, build
}

func keyMAC(secret, msg string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// clusterTracker remembers, within clusterWindow, which client keys and
// ASNs each device key was seen from, and which device keys (by build) each
// client key produced.
type clusterTracker struct {
	mu         sync.Mutex
	deviceIPs  map[string]map[string]time.Time
	deviceASNs map[string]map[uint]time.Time
	ipDevices  map[string]map[string]deviceSeen
}

type deviceSeen struct {
	build string
	at    time.Time
}

func newClusterTracker() *clusterTracker {
	t := &clusterTracker{
		deviceIPs:  make(map[string]map[string]time.Time),
		deviceASNs: make(map[string]map[uint]time.Time),
		ipDevices:  make(map[string]map[string]deviceSeen),
	}
	go t.evictLoop()
	return t
}

// observe records one answer and reports which rules it triggered. Each
// rule fires only on the observation that adds a new IP, ASN or device
// beyond its threshold, so a key isn't charged again for every request
// once it is over.
func (t *clusterTracker) observe(device, build, ip string, asn uint, churnEligible bool, now time.Time) (rotation, churn bool) {
	if device == "" {
		return false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	ips := t.deviceIPs[device]
	if ips == nil {
		ips = make(map[string]time.Time)
		t.deviceIPs[device] = ips
	}
	_, seenIP := ips[ip]
	ips[ip] = now
	if !seenIP && countSince(ips, now) >= rotationIPs {
		rotation = true
	}
	if asn != 0 {
		asns := t.deviceASNs[device]
		if asns == nil {
			asns = make(map[uint]time.Time)
			t.deviceASNs[device] = asns
		}
		_, seenASN := asns[asn]
		asns[asn] = now
		if !seenASN && countSince(asns, now) >= rotationASNs {
			rotation = true
		}
	}

	devs := t.ipDevices[ip]
	if devs == nil {
		devs = make(map[string]deviceSeen)
		t.ipDevices[ip] = devs
	}
	_, seenDev := devs[device]
	devs[device] = deviceSeen{build: build, at: now}
	if churnEligible && !seenDev && build != "" {
		// Count devices of the same build only: many builds behind one
		// address is a NAT full of different people, not a randomiser.
		same := 0
		for _, d := range devs {
			if d.build == build && now.Sub(d.at) < clusterWindow {
				same++
			}
		}
		churn = same >= churnDevices
	}
	return rotation, churn
}

func countSince[K comparable](m map[K]time.Time, now time.Time) int {
	n := 0
	for _, at := range m {
		if now.Sub(at) < clusterWindow {
			n++
		}
	}
	return n
}

func (t *clusterTracker) evictLoop() {
	for range time.Tick(5 * time.Minute) {
		now := time.Now()
		t.mu.Lock()
		for d, m := range t.deviceIPs {
			for k, at := range m {
				if now.Sub(at) >= clusterWindow {
					delete(m, k)
				}
			}
			if len(m) == 0 {
				delete(t.deviceIPs, d)
			}
		}
		for d, m := range t.deviceASNs {
			for k, at := range m {
				if now.Sub(at) >= clusterWindow {
					delete(m, k)
				}
			}
			if len(m) == 0 {
				delete(t.deviceASNs, d)
			}
		}
		for ip, m := range t.ipDevices {
			for k, s := range m {
				if now.Sub(s.at) >= clusterWindow {
					delete(m, k)
				}
			}
			if len(m) == 0 {
				delete(t.ipDevices, ip)
			}
		}
		t.mu.Unlock()
	}
}

// clusterState is what one answer's fingerprint resolved to.
type clusterState struct {
	device, build string
}

// observeCluster derives the answer's cluster keys, applies the rotation
// and churn rules, and adds the keys to hashes for the events log. It
// returns the keys so the caller can apply their tier floor and record
// the answer's outcome against them.
func (h *Handler) observeCluster(r *http.Request, rawFP interface{}, hashes map[string]string, asn uint) (cs clusterState, reasons []string) {
	if hashes == nil || h.clusters == nil {
		return
	}
	c := parseUAClaims(r.UserAgent())
	fp, _ := parseFingerprint(rawFP)
	brave := fp != nil && isBraveClient(fp, r)
	cs.device, cs.build = clusterKeys(h.cfg.HMACSecret, time.Now(), hashes, c, brave)
	if cs.device != "" {
		hashes["device_key"] = cs.device
	}
	if cs.build != "" {
		hashes["build_key"] = cs.build
	}

	ipKey := h.ipKey(r)
	// Brave's device key is built from few inputs; keep it out of the churn
	// rule rather than risk counting one browser as several.
	rotation, churn := h.clusters.observe(cs.device, cs.build, ipKey, asn, !brave, time.Now())
	if rotation {
		h.reputation.RecordDevice(cs.device, reputation.KeyRotation)
		reasons = append(reasons, "device_key_rotation")
	}
	if churn {
		h.reputation.Record(ipKey, 0, reputation.KeyRotation)
		reasons = append(reasons, "device_key_churn")
	}
	return cs, reasons
}
