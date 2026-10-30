package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestPickLocale(t *testing.T) {
	cases := []struct{ header, want string }{
		{"", "en"},
		{"de-DE,de;q=0.9,en;q=0.8", "de"},
		{"en-US,en;q=0.9,de;q=0.8", "en"},
		{"fr-CA", "fr"},
		{"pt-BR,pt;q=0.9", "pt"},
		{"sv-SE,sv;q=0.9", "en"},          // unsupported falls back to English
		{"sv-SE,sv;q=0.9,it;q=0.5", "it"}, // ...or to the next supported preference
		{"en;q=0.5,nl;q=0.9", "nl"},       // q-values beat header order
		{"de;q=0,fr", "fr"},               // q=0 means "not this one"
		{"zh-CN,zh;q=0.9", "zh-Hans"},
		{"zh-TW,zh-Hant;q=0.9", "en"}, // no Traditional Chinese: don't serve Simplified
		{"zh-Hant-HK,ja;q=0.8", "ja"},
		{"*", "en"},
		{"JA-jp", "ja"},
	}
	for _, c := range cases {
		if got := pickLocale(c.header).Lang; got != c.want {
			t.Errorf("pickLocale(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

// Every language carries exactly English's keys, none of them empty except
// where English's own sentence punctuation has no counterpart.
func TestLocalesComplete(t *testing.T) {
	en := messages["en"]
	for lang, m := range messages {
		for k := range en {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: missing %q", lang, k)
			}
		}
		for k, v := range m {
			if _, ok := en[k]; !ok {
				t.Errorf("%s: %q is not an English key", lang, k)
			}
			if v == "" && k != "secured_before" && k != "secured_after" && k != "unverified_after" {
				t.Errorf("%s: %q is empty", lang, k)
			}
		}
	}
}

// A key missing from the map renders as nothing, so check every key the
// templates use exists.
func TestTemplateKeysExist(t *testing.T) {
	ref := regexp.MustCompile(`\.T\.([a-z_]+)`)
	for _, f := range []string{"challenge.html", "pulse.html", "prism.html", "blocked.html", "ratelimited.html", "unverified.html", "footer.html"} {
		b, err := staticFiles.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ref.FindAllStringSubmatch(string(b), -1) {
			if _, ok := messages["en"][m[1]]; !ok {
				t.Errorf("%s uses unknown key %q", f, m[1])
			}
		}
	}
}

// The blocked page follows the browser's language, footer included, and
// says so in Vary.
func TestBlockedPage_Localised(t *testing.T) {
	tpl, err := parsePage("blocked", "blocked.html")
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{blockedTpl: tpl}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	w := httptest.NewRecorder()
	h.serveBlocked(w, r)
	body := w.Body.String()
	for _, want := range []string{`<html lang="de">`, "Sie wurden leider blockiert.", "Warum sehe ich diese Seite?", "Ihre IP:"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if v := w.Header().Get("Vary"); v != "Accept-Language" {
		t.Errorf("Vary = %q", v)
	}
}

// Strings used inside the Prism page's script arrive as JS string literals.
func TestPrismPage_LocalisedScriptStrings(t *testing.T) {
	tpl, err := parsePage("prism", "prism.html")
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	loc := pickLocale("fr")
	if err := tpl.Execute(&sb, map[string]interface{}{"Lang": loc.Lang, "T": loc.T, "Footer": footerData{T: loc.T}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), `btn.textContent = "Vérification…";`) {
		t.Error(`script missing btn.textContent = "Vérification…";`)
	}
}
