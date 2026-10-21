package entry

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/HeatonZ/egress-filter/internal/mitm"
	"github.com/HeatonZ/egress-filter/internal/pool"
)

// The terminating proxy exists for one reason: a SOCKS5 tunnel cannot see HTTP
// status codes, so the forward entry would otherwise be blind to a blocked
// egress. These tests pin that the status really does become visible and that
// it drives the same verdict logic as the reverse entry.

// upstreamServer stands in for the real upstream, reached through a fake
// egress. It records the session id so tests can prove headers survive.
func upstreamServer(t *testing.T, status int, body string, seen *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = r.Header.Get("X-Opencode-Session")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// dialUpstreamFn lets tests bypass Resin and connect straight to the fake
// upstream, since the egress selection is already covered elsewhere.
type testTerminator struct {
	*Terminator
	direct string
}

func newTestTerminator(t *testing.T, p *pool.Pool, ev Evictor) *testTerminator {
	t.Helper()
	dir := t.TempDir()
	ca, err := mitm.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	return &testTerminator{
		Terminator: &Terminator{
			Pool:    p,
			Log:     quietLogger(),
			CA:      ca,
			Evictor: ev,
		},
	}
}

// A blocked egress answered 403 with the abusive-traffic wording. The status
// and body are only visible because TLS was terminated, so this is the case the
// whole design exists for.
func TestTerminateSeesBlockedStatus(t *testing.T) {
	var session string
	up := upstreamServer(t, http.StatusForbidden,
		`{"type":"error","error":{"type":"FreeTierError","message":"OpenCode's free models `+
			`aren't available from your current network because we've detected abusive traffic `+
			`from this IP address."}}`, &session)

	p := seeded()
	ev := &recordingEvictor{}
	tt := newTestTerminator(t, p, ev)
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)

	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxy(t, proxy.URL, tt.CA, upstreamHost(up), "leaseA",
		`{"model":"big-pickle","messages":[{"role":"user","content":"hi"}]}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("client saw status %d, want 403", resp.StatusCode)
	}
	if session == "" {
		t.Fatal("session header did not reach the upstream")
	}
	if resp.StatusCode != 403 {
		t.Fatalf("upstream did not answer 403, got %d", resp.StatusCode)
	}
	// One failure is below the threshold, so the route is only suspect.
	waitFor(t, func() bool { return snapshotOf(p, "leaseA").ConsecFail == 1 })
	if got := snapshotOf(p, "leaseA").State; got != pool.StateSuspect {
		t.Fatalf("state after one blocked = %v, want suspect", got)
	}
	if ev.count() != 0 {
		t.Fatal("evicted below the failure threshold")
	}
}

// The upstream uses the same 403 for "you are not the OpenCode client". That
// says nothing about the egress and must not count toward withdrawal, or a
// single misconfigured caller would drain the pool.
func TestTerminateIgnoresShapeRejection(t *testing.T) {
	up := upstreamServer(t, http.StatusForbidden,
		`{"type":"error","error":{"type":"FreeTierError","message":"OpenCode's free tier can only `+
			`be used from within OpenCode. Download it at https://opencode.ai and keep building."}}`, nil)

	p := seeded()
	tt := newTestTerminator(t, p, &recordingEvictor{})
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxy(t, proxy.URL, tt.CA, upstreamHost(up), "leaseA", `{}`)
	defer resp.Body.Close()

	// The verdict is applied after the response is written, so give the
	// handler a moment before asserting that nothing was recorded.
	time.Sleep(50 * time.Millisecond)
	if got := snapshotOf(p, "leaseA").ConsecFail; got != 0 {
		t.Fatalf("shape rejection counted as %d failures, want 0", got)
	}
	if got := snapshotOf(p, "leaseA").State; got != pool.StateReady {
		t.Fatalf("state = %v, want ready", got)
	}
}

// A 200 proves the egress works.
func TestTerminateSuccessRecordsOK(t *testing.T) {
	up := upstreamServer(t, http.StatusOK, `{"ok":true}`, nil)
	p := seeded()
	tt := newTestTerminator(t, p, &recordingEvictor{})
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxy(t, proxy.URL, tt.CA, upstreamHost(up), "leaseA", `{}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	s := snapshotOf(p, "leaseA")
	if s.State != pool.StateReady || s.ConsecOK == 0 {
		t.Fatalf("state=%v consecOK=%d, want ready with a success", s.State, s.ConsecOK)
	}
}

// A 429 is rate limiting, not a dead egress. Counting it would withdraw every
// route the moment the free tier throttles.
func TestTerminateIgnoresRateLimit(t *testing.T) {
	up := upstreamServer(t, http.StatusTooManyRequests,
		`{"type":"error","error":{"type":"FreeUsageLimitError","message":"Rate limit exceeded."}}`, nil)
	p := seeded()
	tt := newTestTerminator(t, p, &recordingEvictor{})
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxy(t, proxy.URL, tt.CA, upstreamHost(up), "leaseA", `{}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	waitFor(t, func() bool { return snapshotOf(p, "leaseA").ConsecOK > 0 })
	s0 := snapshotOf(p, "leaseA")
	if s0.ConsecFail != 0 {
		t.Fatalf("429 counted as %d failures, want 0 (state=%v verdict=%v detail=%q)",
			s0.ConsecFail, s0.State, s0.LastVerdict, s0.LastError)
	}
}

// Five consecutive failures must withdraw the route and hand it to the
// evictor; the threshold is the user-visible knob, so it is pinned here.
func TestTerminateEvictsAfterThreshold(t *testing.T) {
	up := upstreamServer(t, http.StatusForbidden,
		`{"type":"error","error":{"type":"FreeTierError","message":"OpenCode's free models `+
			`aren't available from your current network because we've detected abusive traffic `+
			`from this IP address."}}`, nil)
	p := seeded()
	ev := &recordingEvictor{}
	tt := newTestTerminator(t, p, ev)
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	for i := 0; i < 4; i++ {
		resp := doThroughProxy(t, proxy.URL, tt.CA, upstreamHost(up), "leaseA", `{}`)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	waitFor(t, func() bool { return snapshotOf(p, "leaseA").ConsecFail >= 4 })
	if got := snapshotOf(p, "leaseA").State; got == pool.StateBlocked {
		t.Fatal("withdrawn before reaching the threshold")
	}

	resp := doThroughProxy(t, proxy.URL, tt.CA, upstreamHost(up), "leaseA", `{}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	waitFor(t, func() bool { return snapshotOf(p, "leaseA").State == pool.StateBlocked })
	if got := snapshotOf(p, "leaseA").State; got != pool.StateBlocked {
		t.Fatalf("state after five failures = %v, want blocked", got)
	}
	if ev.count() == 0 {
		t.Fatal("blocked route was not handed to the evictor")
	}
}

// doThroughProxy sends one request through the terminating proxy and returns
// the upstream response, having trusted the test CA.
func doThroughProxy(t *testing.T, proxyURL string, ca *mitm.CA, upstreamAddr, account, body string) *http.Response {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("test ca is not valid pem")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL(t, proxyURL)),
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+upstreamAddr+"/v1/chat/completions",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Opencode-Session", "ses_test000000000000000000000")
	req.Header.Set("X-Egress-Route", account)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	return resp
}

// The terminating proxy must speak the CONNECT handshake the client expects.
func TestTerminateRejectsNonConnect(t *testing.T) {
	p := seeded()
	tt := newTestTerminator(t, p, nil)
	srv := httptest.NewServer(tt)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// directTo makes the terminator connect straight to the fake upstream instead
// of through Resin. Egress selection is covered by other tests; here the point
// is what happens once the connection exists.
func directTo(t *testing.T, up *httptest.Server) func(account, target string) (net.Conn, error) {
	t.Helper()
	addr := strings.TrimPrefix(up.URL, "https://")
	return func(account, target string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

// upstreamHost is the address the fake upstream's certificate is valid for, so
// the terminator's SNI matches and the upstream TLS handshake succeeds.
func upstreamHost(up *httptest.Server) string {
	return strings.TrimPrefix(up.URL, "https://")
}

// rootsFor trusts the fake upstream's certificate, standing in for the public
// roots production uses.
func rootsFor(t *testing.T, up *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	return pool
}

// waitFor blocks until cond holds. The verdict is applied after the response is
// flushed, so asserting immediately races the handler goroutine.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 3s")
}

// snapshotOf returns the state of one route; Snapshots order is not stable, so
// index-based lookups silently assert against the wrong route.
func snapshotOf(p *pool.Pool, lease string) pool.Snapshot {
	for _, s := range p.Snapshots() {
		if s.Lease == lease {
			return s
		}
	}
	return pool.Snapshot{}
}

// mustURL parses a proxy URL for the test transport.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return u
}
