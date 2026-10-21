package entry

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// testProxyToken is the aggregator's own password, the one clients present.
const testProxyToken = "testtoken"

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
			Token:   testProxyToken,
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

// A 429 counts like every other non-2xx: the route did not serve the request,
// so five in a row rotate it.
func TestTerminateCountsRateLimit(t *testing.T) {
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

	waitFor(t, func() bool { return snapshotOf(p, "leaseA").ConsecFail > 0 })
	s0 := snapshotOf(p, "leaseA")
	if s0.ConsecFail != 1 || s0.State != pool.StateSuspect {
		t.Fatalf("429 recorded as %d failures in state %v, want 1 failure in suspect",
			s0.ConsecFail, s0.State)
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
	return doThroughProxyAs(t, proxyURL, "opencode."+account, testProxyToken, ca, upstreamAddr, body)
}

func doThroughProxyLegacy(t *testing.T, proxyURL string, ca *mitm.CA, upstreamAddr, account, body string) *http.Response {
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

// doThroughProxyAs sends one request through proxyURL authenticating as user,
// so the entry reads the lease from Proxy-Authorization the way a Resin client
// already does.
func doThroughProxyAs(t *testing.T, proxyURL, user, pass string, ca *mitm.CA, upstreamAddr, body string) *http.Response {
	t.Helper()
	u := mustURL(t, proxyURL)
	u.User = url.UserPassword(user, pass)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("test ca is not valid pem")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+upstreamAddr+"/v1/chat/completions",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Opencode-Session", "ses_test000000000000000000000")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	return resp
}

// Resin callers already name the account in the proxy URL. The aggregator must
// honour that too: one URL per lease is what keeps per-account stickiness,
// which automatic selection would quietly destroy.
func TestTerminatePinsLeaseFromProxyAuth(t *testing.T) {
	up := upstreamServer(t, http.StatusOK, `{"ok":true}`, nil)
	p := seeded()
	tt := newTestTerminator(t, p, &recordingEvictor{})
	addr := strings.TrimPrefix(up.URL, "https://")
	var dialed string
	tt.dial = func(account, target string) (net.Conn, error) {
		dialed = account
		return net.Dial("tcp", addr)
	}
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxyAs(t, proxy.URL, "opencode.leaseB", testProxyToken, tt.CA, upstreamHost(up), `{}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if dialed != "leaseB" {
		t.Fatalf("dialed %q, want leaseB (the proxy user must pin the egress)", dialed)
	}
	waitFor(t, func() bool { return snapshotOf(p, "leaseB").ConsecOK > 0 })
}

// A pin that has been withdrawn must fail instead of borrowing a healthy lease.
// Silent fallback is what would make a per-account pool unpredictable.
func TestTerminatePinnedBlockedDoesNotFallBack(t *testing.T) {
	up := upstreamServer(t, http.StatusOK, `{"ok":true}`, nil)
	p := seeded()
	for i := 0; i < 5; i++ {
		p.Record("leaseB", pool.VerdictBlocked, 0, "test block")
	}
	if !p.Blocked("leaseB") {
		t.Fatalf("leaseB state=%v, want blocked", snapshotOf(p, "leaseB").State)
	}
	tt := newTestTerminator(t, p, &recordingEvictor{})
	addr := strings.TrimPrefix(up.URL, "https://")
	var dialed []string
	tt.dial = func(account, target string) (net.Conn, error) {
		dialed = append(dialed, account)
		return net.Dial("tcp", addr)
	}
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxyAs(t, proxy.URL, "opencode.leaseB", testProxyToken, tt.CA, upstreamHost(up), `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if len(dialed) != 0 {
		t.Fatalf("dialed %v, want no dial at all", dialed)
	}
}

// No credentials is refused, so the pool is not an open proxy inside ai-net.
func TestTerminateRequiresCredentials(t *testing.T) {
	up := upstreamServer(t, http.StatusOK, `{"ok":true}`, nil)
	tt := newTestTerminator(t, seeded(), &recordingEvictor{})
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	if line := rawConnect(t, proxy.URL, "", ""); !strings.Contains(line, "407") {
		t.Fatalf("status line = %q, want 407", line)
	}
}

// The aggregator has its own password. An upstream token must not authenticate
// a client here, or sharing a Resin credential would open the aggregator.
func TestTerminateRejectsUpstreamTokenAsClientPassword(t *testing.T) {
	up := upstreamServer(t, http.StatusOK, `{"ok":true}`, nil)
	p := seeded()
	tt := newTestTerminator(t, p, &recordingEvictor{})
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	tt.Upstreams = Upstreams{
		"main": {Name: "main", ProxyAddr: "resin:2260", Token: "resin-secret", BaseURL: "http://resin:2260"},
	}
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	if line := rawConnect(t, proxy.URL, "opencode.leaseA", "resin-secret"); !strings.Contains(line, "407") {
		t.Fatalf("status line = %q, want 407: an upstream token is not a client password", line)
	}
	if line := rawConnect(t, proxy.URL, "opencode.leaseA", testProxyToken); !strings.Contains(line, "200") {
		t.Fatalf("status line = %q, want 200 with the aggregator password", line)
	}
}

// rawConnect sends a bare CONNECT and returns the proxy status line. The client
// helper cannot be used: Go Transport turns a proxy 407 into an error.
func rawConnect(t *testing.T, proxyURL, user, pass string) string {
	t.Helper()
	crlf := string([]byte{13, 10})
	addr := strings.TrimPrefix(proxyURL, "http://")
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	var b strings.Builder
	b.WriteString("CONNECT example.com:443 HTTP/1.1" + crlf + "Host: example.com:443" + crlf)
	if user != "" {
		b.WriteString("Proxy-Authorization: Basic " + basicAuth(user, pass) + crlf)
	}
	b.WriteString(crlf)
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString(byte(10))
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return strings.TrimSpace(line)
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// Two instances can hold a lease of the same name. The client disambiguates
// with "<upstream>/<platform>.<account>", and the request must land on that
// instance rather than whichever route happens to come first.
func TestTerminateUpstreamQualifierSelectsInstance(t *testing.T) {
	up := upstreamServer(t, http.StatusOK, `{"ok":true}`, nil)
	p := pool.New(pool.Options{FailThreshold: 5, RecoverThreshold: 1})
	p.Sync([]pool.Route{
		{Key: "a/lease1", Lease: "lease1", EgressIP: "1.1.1.1", Upstream: "a"},
		{Key: "b/lease1", Lease: "lease1", EgressIP: "2.2.2.2", Upstream: "b"},
	})

	tt := newTestTerminator(t, p, &recordingEvictor{})
	tt.Upstreams = Upstreams{
		"a": {Name: "a", ProxyAddr: "resin-a:2260", Token: "ta"},
		"b": {Name: "b", ProxyAddr: "resin-b:2260", Token: "tb"},
	}
	addr := strings.TrimPrefix(up.URL, "https://")
	tt.dial = func(account, target string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
	tt.UpstreamRoots = rootsFor(t, up)
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	resp := doThroughProxyAs(t, proxy.URL, "b/opencode.lease1", testProxyToken, tt.CA, upstreamHost(up), `{}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	waitFor(t, func() bool { return snapshotByKey(p, "b/lease1").ConsecOK > 0 })
	if got := snapshotByKey(p, "a/lease1").ConsecOK; got != 0 {
		t.Fatalf("instance a recorded %d successes, want 0", got)
	}
}

// snapshotByKey is the lookup multi-instance tests need: two routes can share a
// lease name, so matching on Lease alone is ambiguous.
func snapshotByKey(p *pool.Pool, key string) pool.Snapshot {
	for _, s := range p.Snapshots() {
		if s.Key == key {
			return s
		}
	}
	return pool.Snapshot{}
}

// A client that never offers the user/pass method must be refused, not silently
// let through: RFC 1928 lets the client pick the method, so the server has to
// reject instead of falling back to no-auth.
func TestForwardRequiresUserPassMethod(t *testing.T) {
	f := &Forward{Password: testProxyToken, Platform: "opencode", Log: quietLogger()}
	client, server := net.Pipe()
	defer client.Close()

	go f.handle(server)

	// Offer only no-auth.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0xff {
		t.Fatalf("method reply = %v, want 05 ff (no acceptable methods)", reply)
	}
}

// Without a configured password the entry stays open, which is what the local
// harness and a trusted-network deployment rely on.
func TestForwardAllowsNoAuthWhenNoPassword(t *testing.T) {
	f := &Forward{Platform: "opencode", Log: quietLogger()}
	client, server := net.Pipe()
	defer client.Close()

	go f.handle(server)

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("method reply = %v, want no-auth accepted", reply)
	}
}

// An egress that accepts the connection and then never answers must not pin the
// goroutine forever: the header deadline fires, the attempt is recorded as a
// timeout, and the route goes on probation.
func TestTerminateTimesOutAndCounts(t *testing.T) {
	// The handler parks until the test releases it, so httptest.Server.Close
	// cannot deadlock waiting for a request that never ends.
	release := make(chan struct{})
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	up.StartTLS()
	defer func() { close(release); up.Close() }()

	p := seeded()
	tt := newTestTerminator(t, p, &recordingEvictor{})
	tt.dial = directTo(t, up)
	tt.UpstreamRoots = rootsFor(t, up)
	tt.HeaderTimeout = 150 * time.Millisecond
	proxy := httptest.NewServer(tt)
	defer proxy.Close()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(tt.CA.CertPEM()) {
		t.Fatal("test ca is not valid pem")
	}
	u := mustURL(t, proxy.URL)
	u.User = url.UserPassword("opencode.leaseA", testProxyToken)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+upstreamHost(up)+"/v1/chat/completions",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}

	waitFor(t, func() bool { return snapshotOf(p, "leaseA").LastVerdict == pool.VerdictTimeout })
	if got := snapshotOf(p, "leaseA").State; got != pool.StateSuspect {
		t.Fatalf("state after one timeout = %v, want suspect", got)
	}
}
