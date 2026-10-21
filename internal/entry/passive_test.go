package entry

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// recordingEvictor captures which accounts the data path condemned.
type recordingEvictor struct {
	mu       sync.Mutex
	accounts []string
}

func (r *recordingEvictor) Evict(account string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts = append(r.accounts, account)
}

func (r *recordingEvictor) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.accounts)
}

// gzipped serves body the way the upstream does: compressed, so a classifier
// that reads raw bytes sees nothing.
func gzipped(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	zw := gzip.NewWriter(w)
	io.WriteString(zw, body)
	zw.Close()
}

// The whole point of passive mode: a blocked egress must be recognised from a
// real request, and acted on, without any probe.
func TestPassiveDetectsBlockedEgress(t *testing.T) {
	var calls int
	var mu sync.Mutex
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		gzipped(t, w, 403, `{"type":"error","error":{"type":"FreeTierError","message":`+
			`"OpenCode's free models aren't available from your current network because we've detected `+
			`abusive traffic from this IP address. This isn't related to your account."}}`)
	}))
	defer fake.Close()

	p := seeded()
	ev := &recordingEvictor{}
	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	r.Evictor = ev
	srv := httptest.NewServer(r)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/inference/v1/chat/completions")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("status = %d, want 403 passthrough", resp.StatusCode)
		}
	}

	var snap pool.Snapshot
	for _, s := range p.Snapshots() {
		if s.Key == "leaseA" {
			snap = s
		}
	}
	if snap.State != pool.StateBlocked {
		t.Fatalf("state = %v, want blocked after five gzipped blocked responses", snap.State)
	}
	if snap.LastVerdict != pool.VerdictBlocked {
		t.Fatalf("verdict = %v, want blocked", snap.LastVerdict)
	}
	if ev.count() == 0 {
		t.Fatal("evictor was never called for a blocked egress")
	}
}

// A 403 whose body says the request shape was wrong is a configuration
// problem. Acting on it would drain the pool for nothing.
func TestPassiveIgnoresShapeRejection(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzipped(t, w, 403, `{"type":"error","error":{"type":"FreeTierError","message":`+
			`"OpenCode's free tier can only be used from within OpenCode. Download it at `+
			`https://opencode.ai and keep building."}}`)
	}))
	defer fake.Close()

	p := seeded()
	ev := &recordingEvictor{}
	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	r.Evictor = ev
	srv := httptest.NewServer(r)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/x")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	for _, s := range p.Snapshots() {
		if s.Key != "leaseA" {
			continue
		}
		if s.State != pool.StateReady {
			t.Fatalf("shape rejection changed state to %v; it must be ignored", s.State)
		}
	}
	if ev.count() != 0 {
		t.Fatalf("shape rejection triggered %d evictions; it must trigger none", ev.count())
	}
}

// A 200 must clear a route's failures, otherwise a route that recovered can
// never be trusted again under passive-only observation.
func TestPassiveSuccessClearsFailures(t *testing.T) {
	var mode int
	var mu sync.Mutex
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		m := mode
		mu.Unlock()
		if m == 0 {
			gzipped(t, w, 403, `{"error":{"message":"abusive traffic from this IP address"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: ok\n\n")
	}))
	defer fake.Close()

	p := seeded()
	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	// One failure: suspect but still selectable.
	resp, _ := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/x")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	mu.Lock()
	mode = 1
	mu.Unlock()
	resp, err := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/x")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	for _, s := range p.Snapshots() {
		if s.Key == "leaseA" {
			if s.State != pool.StateReady || s.ConsecFail != 0 {
				t.Fatalf("success did not clear failures: state=%v fail=%d", s.State, s.ConsecFail)
			}
		}
	}
}

// 400 means the egress carried the request and the upstream rejected its
// content (context length is the common case). It must not count as a failure.
func TestPassiveBadRequestIsNotFailure(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzipped(t, w, 400, `{"error":{"type":"invalid_request_error","message":"context_length_exceeded"}}`)
	}))
	defer fake.Close()

	p := seeded()
	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	for i := 0; i < 4; i++ {
		resp, _ := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/x")
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	for _, s := range p.Snapshots() {
		if s.Key == "leaseA" && s.State != pool.StateReady {
			t.Fatalf("context-length 400 demoted the route to %v", s.State)
		}
	}
}

// 5xx is the upstream's own problem; the egress is fine.
func TestPassiveServerErrorIsNotEvidence(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	defer fake.Close()

	p := seeded()
	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	for i := 0; i < 4; i++ {
		resp, _ := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/x")
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	for _, s := range p.Snapshots() {
		if s.Key == "leaseA" && s.State != pool.StateReady {
			t.Fatalf("502 demoted the route to %v; only a blocked egress may", s.State)
		}
	}
}

var _ = time.Second
