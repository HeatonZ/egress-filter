package probe

import (
	"strings"
	"testing"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// The two 403 families must map to different verdicts. Collapsing them is the
// bug that makes a pool either churn forever or never clean up.
func TestClassifyForbiddenFamilies(t *testing.T) {
	cases := []struct {
		name string
		body string
		want pool.Verdict
	}{
		{"abusive traffic is a blocked egress",
			`{"error":{"message":"abusive traffic from this IP address"}}`, pool.VerdictBlocked},
		{"network restriction is a blocked egress",
			`{"error":{"message":"OpenCode's free models aren't available from your current network"}}`,
			pool.VerdictBlocked},
		{"deviation rejection is the request shape, not the egress",
			`{"error":{"message":"FreeTierError: can only be used from within OpenCode"}}`,
			pool.VerdictBadRequest},
		{"unrecognised 403 must not condemn the route",
			`{"error":{"message":"forbidden"}}`, pool.VerdictUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(403, tc.body, time.Millisecond)
			if got.Verdict != tc.want {
				t.Fatalf("verdict = %v, want %v (detail %q)", got.Verdict, tc.want, got.Detail)
			}
		})
	}
}

func TestClassifyStatuses(t *testing.T) {
	cases := []struct {
		status int
		want   pool.Verdict
	}{
		{200, pool.VerdictOK},
		{204, pool.VerdictOK},
		{400, pool.VerdictBadRequest}, // context length, malformed body
		{429, pool.VerdictUnknown},    // capacity, not a blocked egress
		{500, pool.VerdictUnknown},
		{502, pool.VerdictUnknown},
		{504, pool.VerdictUnknown},
	}
	for _, tc := range cases {
		got := classify(tc.status, "", time.Millisecond)
		if got.Verdict != tc.want {
			t.Errorf("status %d: verdict = %v, want %v", tc.status, got.Verdict, tc.want)
		}
	}
}

// Gzip bytes never contain the marker text, so a classifier that forgets to
// decompress silently reports "nothing matched". This is the exact mistake that
// once led to the conclusion that no egress was blocked.
func TestDecodeGzip(t *testing.T) {
	// A realistic error body: gzip only compresses above a size threshold, and a
	// tiny body is stored verbatim, which would make this test pass for the
	// wrong reason.
	body := `{"error":{"type":"FreeTierError","message":"abusive traffic from this IP address","trace":"` +
		strings.Repeat("x", 512) + `"}}`
	compressed := gzipBytes(t, body)

	if strings.Contains(string(compressed), "abusive") {
		t.Fatal("precondition failed: raw gzip unexpectedly contains the marker")
	}
	got := decode(compressed, "gzip")
	if !strings.Contains(got, "abusive traffic") {
		t.Fatalf("decode did not inflate the body, got %q", got)
	}
	if v := classify(403, got, time.Millisecond).Verdict; v != pool.VerdictBlocked {
		t.Fatalf("gzip 403 body should classify as blocked, got %v", v)
	}
}

func TestSessionIDShape(t *testing.T) {
	id := SessionID("freeproxy35", time.Unix(1760000000, 0))
	if !strings.HasPrefix(id, "ses_") {
		t.Fatalf("session id must carry the ses_ prefix, got %q", id)
	}
	if len(id) != 30 {
		t.Fatalf("session id length = %d, want 30 (ses_ + 12 hex + 14 base62)", len(id))
	}
	other := SessionID("freeproxy36", time.Unix(1760000000, 0))
	if other == id {
		t.Fatal("different routes must not share a session id")
	}
}

func TestBodyCarriesFullToolDescription(t *testing.T) {
	body := string(DefaultIdentity().Body("ses_0000000000000000000000000000"))
	want := DefaultIdentity().ToolDesc
	if !strings.Contains(body, want) {
		t.Fatal("tool description must appear verbatim; a truncated one is rejected by the upstream")
	}
	if !strings.Contains(body, `"max_tokens":1`) || !strings.Contains(body, `"stream":true`) {
		t.Fatal("body must keep the minimal streaming shape")
	}
}
