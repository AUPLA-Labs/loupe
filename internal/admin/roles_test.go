package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

func TestViewerCannotPost(t *testing.T) {
	hash := testHash(t, "pw")
	s, h := usersServer(t, "",
		config.AdminUser{Username: "pat", PasswordHash: hash, Role: config.RoleAdmin},
		config.AdminUser{Username: "vera", PasswordHash: hash, Role: config.RoleViewer})
	c := signIn(t, h, "vera")

	if w := get(h, "/api/settings", c); w.Code != http.StatusOK {
		t.Fatalf("viewer GET /api/settings = %d, want 200", w.Code)
	}
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://console.lan"+path, strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		r.AddCookie(c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := post("/api/settings", `{"values":{"abuse.rate_limit.burst":30}}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "read-only account") {
		t.Fatalf("viewer POST /api/settings = %d %q, want 403 read-only account", w.Code, w.Body)
	}
	// A refused write must leave no audit entry (the login is the only one).
	for _, e := range s.audit.Load().Recent(10, time.Time{}) {
		if e.Action == "settings_save" {
			t.Fatalf("refused viewer write was audited: %+v", e)
		}
	}
	if w := post("/api/logout", ""); w.Code != http.StatusNoContent {
		t.Fatalf("viewer POST /api/logout = %d, want 204", w.Code)
	}
}

func TestAllowByAccess(t *testing.T) {
	s := NewServer(newTestStore(t, 10), nil, "", AuthOptions{})
	viewer := config.AdminUser{Username: "vera", Role: config.RoleViewer}
	admin := config.AdminUser{Username: "pat", Role: config.RoleAdmin}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	for _, tc := range []struct {
		name   string
		user   config.AdminUser
		method string
		access string
		want   int
	}{
		{"viewer reads", viewer, "GET", "", 200},
		{"viewer head", viewer, "HEAD", "", 200},
		{"viewer writes", viewer, "POST", "", 403},
		{"viewer self", viewer, "POST", "self", 200},
		{"viewer admin-only read", viewer, "GET", "admin", 403},
		{"admin admin-only read", admin, "GET", "admin", 200},
		{"admin writes", admin, "POST", "", 200},
		{"unknown role is read-only", config.AdminUser{Username: "x", Role: "root"}, "POST", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := route{pattern: tc.method + " /x", access: tc.access}
			w := httptest.NewRecorder()
			s.allow(rt, ok)(w, withUser(httptest.NewRequest(tc.method, "/x", nil), tc.user))
			if w.Code != tc.want {
				t.Fatalf("%s %q as %s = %d, want %d", tc.method, tc.access, tc.user.Role, w.Code, tc.want)
			}
			if tc.want == 403 && !strings.Contains(w.Body.String(), "read-only account") {
				t.Fatalf("403 body = %q, want read-only account", w.Body)
			}
		})
	}

	// Without a user in the context nothing is allowed.
	w := httptest.NewRecorder()
	s.allow(route{pattern: "GET /x"}, ok)(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("request with no user = %d, want 401", w.Code)
	}
}
