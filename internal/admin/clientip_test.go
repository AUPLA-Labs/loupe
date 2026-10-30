package admin

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/clientip"
	"github.com/AUPLA-Labs/loupe/internal/config"
)

// Behind a trusted proxy every sign-in arrives from the proxy's address;
// the throttle must count each visitor behind it on their own.
func TestSignInThrottleUsesProxiedAddress(t *testing.T) {
	s, h := usersServer(t, "", config.AdminUser{Username: "pat", PasswordHash: testHash(t, "pw"), Role: config.RoleAdmin})
	rs, err := clientip.New([]string{"loopback"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	s.SetClientIP(rs)
	from := func(visitor string) func(*http.Request) {
		return func(r *http.Request) {
			r.RemoteAddr = "127.0.0.1:5555"
			r.Header.Set("X-Forwarded-For", visitor)
		}
	}
	wrong := url.Values{"username": {"pat"}, "password": {"nope"}}
	for i := 0; i < 10; i++ {
		postLogin(h, wrong, from("198.51.100.4"))
	}
	if w := postLogin(h, wrong, from("198.51.100.4")); w.Code != http.StatusTooManyRequests {
		t.Errorf("throttled visitor got %d, want 429", w.Code)
	}
	if w := postLogin(h, wrong, from("198.51.100.5")); w.Code == http.StatusTooManyRequests {
		t.Error("another visitor behind the same proxy was throttled too")
	}
}
