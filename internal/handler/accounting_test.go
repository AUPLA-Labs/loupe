package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsDocumentNavigation_NonDocumentSecFetchDestIsExcluded(t *testing.T) {
	// A prefetch/subresource request commonly still carries Accept: text/html,
	// so it is Sec-Fetch-Dest (when present) that must decide, not Accept —
	// otherwise a prefetch would be wrongly treated as a document navigation
	// and the 403 rule below (Step 3) would never apply to it.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	if isDocumentNavigation(r) {
		t.Fatal("Sec-Fetch-Dest: empty must not count as a document navigation, regardless of Accept")
	}
}
