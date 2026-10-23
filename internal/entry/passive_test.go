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
// snapshotFor looks a route up by key. Snapshots order is not stable, so an
// index-based lookup silently asserts against the wrong route.
func snapshotFor(p *pool.Pool, key string) pool.Snapshot {
	for _, s := range p.Snapshots() {
		if s.Key == key {
			return s
		}
	}
	return pool.Snapshot{}
}

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

	// The first blocked 403 withdraws the route, so only the first request can
	// pass a 403 through; the rest already find no egress. Send one and assert
	// the rotation, then let the pool report the withdrawal.
	resp, err := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/inference/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403 passthrough", resp.StatusCode)
	}
	waitFor(t, func() bool { return snapshotFor(p, "leaseA").ConsecFail >= 1 })
	var snap pool.Snapshot
	for _, s := range p.Snapshots() {
		if s.Key == "leaseA" {
			snap = s
		}
	}
	if snap.State != pool.StateBlocked {
		t.Fatalf("state = %v, want blocked after one gzipped blocked response", snap.State)
	}
	if snap.LastVerdict != pool.VerdictBlocked {
		t.Fatalf("verdict = %v, want blocked", snap.LastVerdict)
	}
	if ev.count() == 0 {
		t.Fatal("evictor was never called for a blocked egress")
	}
}

// A 403 whose body blames the request shape still means this route did not
// serve the request, so it counts: five in a row withdraw the route, exactly
// like a blocked egress.
func TestPassiveShapeRejectionCounts(t *testing.T) {
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

	// The verdict is applied after the response is written, so wait for it.
	waitFor(t, func() bool { return snapshotOf(p, "leaseA").State == pool.StateBlocked })
	if ev.count() == 0 {
		t.Fatal("a withdrawn route was never handed to the evictor")
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
			// An ordinary failure, not a blocked 403: a blocked 403 withdraws the
			// route on its first response now, so it cannot build a suspect
			// state that a later success is supposed to clear.
			gzipped(t, w, 500, `{"error":{"message":"upstream exploded"}}`)
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

	// The verdict is recorded after the response is flushed, so waiting on the
	// condition is the only stable assertion: reading straight after the body
	// closes races the writer and fails intermittently on a slower machine.
	waitFor(t, func() bool {
		s := snapshotFor(p, "leaseA")
		return s.State == pool.StateReady && s.ConsecFail == 0
	})
}

// 400 counts too: the route did not serve the request. Four of them leave the
// route on probation, the fifth withdraws it.
func TestPassiveBadRequestCounts(t *testing.T) {
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
		if s.Key == "leaseA" && s.State != pool.StateSuspect {
			t.Fatalf("four 400s left the route in %v, want suspect", s.State)
		}
	}
}

// A 5xx is a failure like any other: five in a row withdraw the route, because
// a route that keeps returning 5xx is not serving traffic whatever the cause.
func TestPassiveServerErrorCounts(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	defer fake.Close()

	p := seeded()
	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		resp, _ := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/x")
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	states := map[string]pool.State{}
	for _, snap := range p.Snapshots() {
		states[snap.Key] = snap.State
	}
	if states["leaseA"] != pool.StateBlocked {
		t.Fatalf("five 502s left leaseA in %v, want blocked", states["leaseA"])
	}
	if states["leaseB"] != pool.StateReady {
		t.Fatalf("leaseB was demoted to %v although it never failed", states["leaseB"])
	}
}

var _ = time.Second
