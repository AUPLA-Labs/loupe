package admin

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/clientip"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

func allowServer(t *testing.T, allow []string) http.Handler {
	t.Helper()
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), filepath.Join(t.TempDir(), "config.yaml"), AuthOptions{})
	if err := s.SetAllow(allow); err != nil {
		t.Fatal(err)
	}
	rs, err := clientip.New([]string{"private", "loopback"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	s.SetClientIP(rs)
	return s.Handler()
}

func getFrom(h http.Handler, peer string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://console.lan/login", nil)
	r.RemoteAddr = peer
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAdminAllowDefault(t *testing.T) {
	cfg, err := config.LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := allowServer(t, cfg.Admin.Allow)
	for _, peer := range []string{"192.168.1.5:4000", "127.0.0.1:4000", "[::1]:4000", "[fd00::5]:4000"} {
		if w := getFrom(h, peer, nil); w.Code == http.StatusForbidden {
			t.Errorf("%s refused", peer)
		}
	}
	w := getFrom(h, "203.0.113.9:4000", nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "admin.allow") {
		t.Errorf("public peer = %d %q, want 403 naming admin.allow", w.Code, w.Body)
	}
}

func TestAdminAllowUsesSocketPeer(t *testing.T) {
	h := allowServer(t, []string{"loopback", "private"})
	if w := getFrom(h, "203.0.113.9:4000", map[string]string{"X-Forwarded-For": "192.168.1.5"}); w.Code != http.StatusForbidden {
		t.Errorf("forged X-Forwarded-For let a public peer in: %d", w.Code)
	}
}

func TestAdminAllowCustom(t *testing.T) {
	h := allowServer(t, []string{"100.64.0.0/10"})
	if w := getFrom(h, "100.100.1.1:4000", nil); w.Code == http.StatusForbidden {
		t.Error("tailnet peer refused")
	}
	if w := getFrom(h, "192.168.1.5:4000", nil); w.Code != http.StatusForbidden {
		t.Errorf("LAN peer outside the list = %d, want 403", w.Code)
	}
}

func TestSetupURLListsLANAddresses(t *testing.T) {
	old := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = old })
	interfaceAddrs = func() ([]ifaceAddr, error) {
		var out []ifaceAddr
		for _, c := range [][2]string{
			{"eth1", "203.0.113.4"}, {"eth0", "192.168.1.20"}, {"eth0", "fd00::5"},
			{"docker0", "172.17.0.1"}, {"br-1a2b", "172.18.0.1"}, {"lo", "127.0.0.1"}, {"lo", "::1"},
		} {
			out = append(out, ifaceAddr{c[0], netip.MustParseAddr(c[1])})
		}
		return out, nil
	}
	s, _ := setupServer(t, t.TempDir())
	s.listen = "0.0.0.0:9090"
	tok := s.auth.setupToken()
	want := []string{"http://192.168.1.20:9090/setup/" + tok, "http://127.0.0.1:9090/setup/" + tok}
	if got := s.SetupURLs(); !slices.Equal(got, want) {
		t.Errorf("SetupURLs = %v, want %v", got, want)
	}
}

// A machine with only private IPv6 on its network lists that.
func TestSetupURLIPv6Only(t *testing.T) {
	old := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = old })
	interfaceAddrs = func() ([]ifaceAddr, error) {
		return []ifaceAddr{{"eth0", netip.MustParseAddr("fd00::5")}, {"lo", netip.MustParseAddr("127.0.0.1")}}, nil
	}
	s, _ := setupServer(t, t.TempDir())
	s.listen = ":9090"
	tok := s.auth.setupToken()
	want := []string{"http://[fd00::5]:9090/setup/" + tok, "http://127.0.0.1:9090/setup/" + tok}
	if got := s.SetupURLs(); !slices.Equal(got, want) {
		t.Errorf("SetupURLs = %v, want %v", got, want)
	}
}
