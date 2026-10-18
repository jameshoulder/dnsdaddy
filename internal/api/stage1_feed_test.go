package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestStage1FeedAdmissionErrorsDoNotEchoSecrets(t *testing.T) {
	h := newHarness(t)
	h.login()
	for _, raw := range []string{"https://user:synthetic-password@feed.example/list", "http://feed.example/synthetic-path-secret?key=synthetic-query-secret", "https://feed.example/%synthetic-path-secret"} {
		resp, body := h.do("POST", "/api/v1/feeds", map[string]any{"name": "synthetic", "url": raw})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unsafe URL status %d", resp.StatusCode)
		}
		for _, secret := range []string{"synthetic-password", "synthetic-path-secret", "synthetic-query-secret"} {
			if strings.Contains(string(body), secret) {
				t.Fatal("HTTP error leaked URL authentication material")
			}
		}
	}
}
