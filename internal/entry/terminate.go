// TLS-terminating forward proxy: the only way a forward entry can see status
// codes.
//
// The client CONNECTs to us, we complete a TLS handshake with a certificate
// signed by our own CA, read the HTTP request in the clear, then open our own
// TLS connection to the upstream through the chosen egress. The response status
// and body prefix are then visible, so the same verdict logic the reverse entry
// uses applies here too.
package entry

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HeatonZ/egress-filter/internal/mitm"
	"github.com/HeatonZ/egress-filter/internal/pool"
	"github.com/HeatonZ/egress-filter/internal/probe"
)

// Terminator handles CONNECT requests by terminating TLS.
type Terminator struct {
	Pool *pool.Pool
	Log  *slog.Logger
	CA   *mitm.CA

	// Upstream is Resin's SOCKS5 endpoint, used to reach the real host through
	// the chosen egress.
	Upstream string
	Token    string
	// Upstreams resolves a route to the Resin instance that owns its lease.
	Upstreams   Upstreams
	Platform    string
	DialTimeout time.Duration

	// CaptureBytes bounds how much of a non-2xx body is read for classification.
	CaptureBytes int64
	// Evictor is notified when live traffic proves an egress blocked.
	Evictor Evictor
	// UpstreamRoots verifies the upstream certificate. Nil means system roots.
	UpstreamRoots *x509.CertPool

	// dial is the egress hop. It is a field so tests can substitute a direct
	// connection without standing up Resin; production leaves it nil.
	dial func(account, target string) (net.Conn, error)
}

// dialEgress opens the hop to target through account's egress.
func (t *Terminator) dialEgress(route pool.Route, target string) (net.Conn, error) {
	if t.dial != nil {
		return t.dial(route.Lease, target)
	}
	return t.dialThroughEgress(route, target)
}

// ServeHTTP implements the CONNECT handshake and hands off to the tunnel.
func (t *Terminator) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, port = req.Host, "443"
	}

	// The entry speaks the same dialect Resin does: the proxy user name is
	// "platform.account" and the password is the shared egress token. Checking
	// the password matters because the lease list is effectively a capability:
	// anyone who can name a lease can spend that lease's quota.
	user, pass, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok || !t.authorized(pass) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="egress-filter"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	// The pin belongs to the tunnel, so it is read once here; a per-request
	// X-Egress-Route header can still override it for clients that share one
	// tunnel across several accounts.
	pinned := user

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Tell the client the tunnel is open before the TLS handshake; this is what
	// makes the client believe it is talking to the real host.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// Bytes the client already pipelined past CONNECT belong to the TLS
	// handshake, so the handshake must read through the buffered reader first.
	// The reader is used unconditionally: choosing between it and conn based on
	// Buffered() races with a client that sends its ClientHello immediately.
	client := io.MultiReader(brw.Reader, conn)

	leaf, err := t.CA.Leaf(host)
	if err != nil {
		t.Log.Warn("sign leaf", "host", host, "error", err)
		return
	}
	tlsConn := tls.Server(&bufferedConn{Conn: conn, r: client},
		&tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err := tlsConn.Handshake(); err != nil {
		t.Log.Debug("client handshake failed", "host", host, "error", err)
		return
	}
	defer tlsConn.Close()

	t.handleStream(tlsConn, host, port, pinned)
}

// bufferedConn lets the TLS server read from an already-buffered reader.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// handleStream reads HTTP requests off the decrypted connection and forwards
// each through an egress, so status codes become visible.
func (t *Terminator) handleStream(client *tls.Conn, host, port, pinned string) {
	br := bufio.NewReader(client)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if !t.roundTrip(client, req, host, port, pinned) {
			return
		}
	}
}

// roundTrip forwards one request and writes the response back.
func (t *Terminator) roundTrip(client *tls.Conn, req *http.Request, host, port, pinned string) bool {
	// The tunnel pin is the default; a request header wins when present so a
	// caller that multiplexes several accounts over one tunnel still works.
	if perRequest := req.Header.Get("X-Egress-Route"); perRequest != "" {
		pinned = perRequest
	}
	route, account := t.choose(pinned)
	if account == "" {
		msg := "no healthy egress"
		if pinned != "" && pinned != "auto" {
			// The caller asked for one specific account; borrowing another
			// egress would silently break its session affinity.
			msg = "pinned egress unavailable"
		}
		writeStatus(client, http.StatusServiceUnavailable, msg)
		return false
	}

	upstreamConn, err := t.dialEgress(route, net.JoinHostPort(host, port))
	if err != nil {
		t.Pool.SetError(route.Key, err.Error())
		t.Pool.Record(route.Key, pool.VerdictUnknown, 0, "egress dial: "+err.Error())
		writeStatus(client, http.StatusBadGateway, "egress unreachable")
		return false
	}
	defer upstreamConn.Close()

	// Verify the real upstream certificate. Skipping this would let any
	// machine on the egress path impersonate the upstream, and would also hide
	// a broken egress behind a silent TLS downgrade.
	tlsUp := tls.Client(upstreamConn, &tls.Config{
		ServerName: host,
		RootCAs:    t.UpstreamRoots,
	})
	if err := tlsUp.Handshake(); err != nil {
		t.Pool.Record(route.Key, pool.VerdictUnknown, 0, "upstream tls: "+err.Error())
		writeStatus(client, http.StatusBadGateway, "upstream tls failed")
		return false
	}
	defer tlsUp.Close()

	if err := req.Write(tlsUp); err != nil {
		return false
	}

	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(tlsUp), req)
	if err != nil {
		t.Pool.Record(route.Key, pool.VerdictUnknown, time.Since(start), "read response: "+err.Error())
		return false
	}
	defer resp.Body.Close()

	// Capture the body prefix by wrapping the reader rather than reading ahead:
	// resp.Write streams the body itself, so reading first would either lose
	// bytes or duplicate them. Only non-2xx bodies are worth keeping, and only
	// the prefix, because a 403 explains itself in the first line while a 200
	// SSE stream never ends.
	cap := &captureReader{src: resp.Body}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		cap.limit = t.CaptureBytes
		if cap.limit <= 0 {
			cap.limit = 8 << 10
		}
	}
	resp.Body = cap

	if err := resp.Write(client); err != nil {
		return false
	}
	captured := cap.buf

	t.observe(route.Key, resp.StatusCode, resp.Header.Get("Content-Encoding"), captured, time.Since(start))

	// Connection reuse is only safe when the response was fully framed.
	return !resp.Close && req.Close == false
}

func (t *Terminator) observe(key string, status int, encoding string, prefix []byte, latency time.Duration) {
	if status >= 200 && status < 300 {
		t.Pool.Record(key, pool.VerdictOK, latency, "served live traffic")
		return
	}
	if status == http.StatusForbidden {
		res := probe.Classify(status, probe.Decode(prefix, encoding), latency)
		if res.Verdict == pool.VerdictBlocked {
			t.Pool.Record(key, pool.VerdictBlocked, latency, res.Detail)
			// Only ask for deletion once the threshold is actually reached. The
			// scheduler's ClaimEviction would also refuse below it, but handing
			// every single blocked response to it would queue pointless work and
			// make the evictor's log look like it fired on one failure.
			if t.Evictor != nil && t.Pool.Blocked(key) {
				t.Log.Info("egress blocked by live traffic", "route", key, "detail", res.Detail)
				t.Evictor.Evict(key)
			}
		}
		return
	}
	if status == http.StatusBadRequest {
		t.Pool.Record(key, pool.VerdictBadRequest, latency, "upstream rejected request content")
		return
	}
	// 429 and 5xx say nothing about the egress.
}

// authorized reports whether pass is this entry's own password. The entry is an
// aggregator: clients authenticate here with the token configured for it, and
// each Resin instance behind it is reached with that instance's own token. The
// two secrets are deliberately separate, so rotating one does not touch the other.
func (t *Terminator) authorized(pass string) bool {
	return t.Token != "" && pass == t.Token
}

func (t *Terminator) choose(pinned string) (pool.Route, string) {
	if route, ok := PinRoute(t.Upstreams, pinned); ok {
		// The caller names the lease, so it is used whether or not discovery has
		// listed it yet: Resin creates it on demand. Only a lease traffic has
		// already proved blocked is refused, because that is positive evidence
		// rather than absence of evidence.
		route = t.Pool.Ensure(route)
		if t.Pool.Blocked(route.Key) {
			return pool.Route{}, ""
		}
		return route, route.Key
	}
	route, ok := t.Pool.Pick()
	if !ok {
		return pool.Route{}, ""
	}
	return route, route.Key
}

// dialThroughEgress opens a SOCKS5 CONNECT to Resin and then to target.
func (t *Terminator) dialThroughEgress(route pool.Route, target string) (net.Conn, error) {
	f := &Forward{
		Pool:        t.Pool,
		Log:         t.Log,
		Upstream:    t.Upstream,
		Token:       t.Token,
		Upstreams:   t.Upstreams,
		Platform:    t.Platform,
		DialTimeout: t.DialTimeout,
	}
	return f.dialUpstream(route, target)
}

// captureReader keeps the first limit bytes that pass through it while letting
// every byte continue to the caller, so streaming is unaffected.
type captureReader struct {
	src   io.ReadCloser
	limit int64
	buf   []byte
}

func (c *captureReader) Close() error { return c.src.Close() }

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 && int64(len(c.buf)) < c.limit {
		room := c.limit - int64(len(c.buf))
		take := int64(n)
		if take > room {
			take = room
		}
		c.buf = append(c.buf, p[:take]...)
	}
	return n, err
}

func writeStatus(w io.Writer, code int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

var _ = strconv.Itoa
var _ = strings.TrimSpace
