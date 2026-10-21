// Package entry exposes the pool through the two proxy shapes the callers
// already speak: a reverse-proxy URL and a forward proxy.
//
// Keeping the reverse-proxy path identical to Resin's is deliberate. Every
// existing caller already builds ".../{token}/{platform}.{account}/{proto}/host".
// If the filter accepts that same shape, migrating a caller is a host swap
// rather than a config rewrite, and rolling back is the same one-line swap.
package entry

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
	"github.com/HeatonZ/egress-filter/internal/probe"
	"github.com/HeatonZ/egress-filter/internal/resin"
)

// Evictor removes a route whose egress the upstream refused.
//
// Declared here rather than imported from the app package to keep the data path
// free of the control loop, and to keep the dependency pointing one way.
type Evictor interface {
	Evict(account string)
}

// Reverse proxies HTTP requests through a chosen lease.
type Reverse struct {
	Pool     *pool.Pool
	Upstream string // e.g. http://resin:2260 fallback
	// Upstreams resolves a route to its Resin instance, so several instances can
	// sit behind one reverse entry.
	Upstreams Upstreams
	Platform  string // e.g. opencode

	// Transport is shared across requests so connections are reused. Without
	// this, every SSE stream would pay a fresh TCP+TLS handshake to the
	// upstream.
	Transport *http.Transport
	Log       *slog.Logger

	// CaptureBytes is how much of a non-2xx body is kept for classification.
	CaptureBytes int64

	// Evictor is called when live traffic proves an egress is blocked. Nil
	// disables eviction, which is the safe default for a first deployment.
	Evictor Evictor
}

// NewReverse builds the reverse entry point.
func NewReverse(p *pool.Pool, upstream, platform string, log *slog.Logger) *Reverse {
	return &Reverse{
		Pool:     p,
		Upstream: strings.TrimRight(upstream, "/"),
		Platform: platform,
		Transport: &http.Transport{
			// No proxy of its own: name resolution and egress are the upstream
			// proxy's job, not ours.
			Proxy:               nil,
			MaxIdleConns:        512,
			MaxIdleConnsPerHost: 128,
			IdleConnTimeout:     90 * time.Second,
			// Streaming responses must not be buffered by the transport.
			DisableCompression: true,
			// Long SSE responses need a long window; the caller controls the
			// deadline.
			ResponseHeaderTimeout: 60 * time.Second,
		},
		Log:          log,
		CaptureBytes: 8 << 10,
	}
}

// ServeHTTP handles /{token}/{platform}.{account}/{proto}/{host}/{rest...}.
func (r *Reverse) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	segs := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
	if len(segs) < 4 {
		http.Error(w, `{"error":"expected /{token}/{platform}.{account}/{proto}/{host}/..."}`, http.StatusBadRequest)
		return
	}

	token := segs[0]
	identity := segs[1]
	proto := segs[2]
	host := segs[3]
	rest := strings.Join(segs[4:], "/")

	platform, requested, ok := splitIdentity(identity)
	if !ok || !strings.EqualFold(platform, r.Platform) {
		http.Error(w, `{"error":"identity does not match the configured platform"}`, http.StatusBadRequest)
		return
	}

	route, used := r.choose(requested, req.Header)
	if used == "" {
		http.Error(w, `{"error":"no healthy egress available"}`, http.StatusServiceUnavailable)
		return
	}

	targetPath := "/" + token + "/" + platform + "." + used + "/" + proto + "/" + host
	if rest != "" {
		targetPath += "/" + rest
	}
	base := r.Upstream
	if up, ok := r.Upstreams.Resolve(route.Upstream); ok && up.BaseURL != "" {
		base = up.BaseURL
	}
	target := base + targetPath
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}

	out, err := http.NewRequestWithContext(req.Context(), req.Method, target, req.Body)
	if err != nil {
		http.Error(w, `{"error":"build upstream request failed"}`, http.StatusBadGateway)
		return
	}
	copyHeaders(out.Header, req.Header)
	out.Header.Set("X-Egress-Route", route.Key)

	start := time.Now()
	resp, err := r.Transport.RoundTrip(out)
	if err != nil {
		// A transport failure is real evidence about the route.
		r.Pool.SetError(route.Key, err.Error())
		r.Pool.Record(route.Key, pool.VerdictUnknown, time.Since(start), "reverse transport: "+err.Error())
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("X-Egress-Route", route.Key)
	w.WriteHeader(resp.StatusCode)

	// Stream straight through. Only a non-2xx body is worth keeping for
	// classification: a 200 SSE stream is large, and inflating a truncated
	// prefix of it costs CPU on the hot path for no verdict value.
	var captured bytes.Buffer
	var reader io.Reader = resp.Body
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limit := r.CaptureBytes
		if limit <= 0 {
			limit = 8 << 10
		}
		reader = io.TeeReader(resp.Body, &capWriter{buf: &captured, limit: limit})
	}
	n, copyErr := io.Copy(flushWriter{w}, reader)
	latency := time.Since(start)

	r.observe(route.Key, resp.StatusCode, resp.Header.Get("Content-Encoding"),
		captured.Bytes(), latency, copyErr)
	r.Log.Debug("reverse", "route", route.Key, "status", resp.StatusCode, "bytes", n,
		"latency_ms", latency.Milliseconds(), "stream_err", copyErr)
}

// choose resolves which account to send the request through.
//
// The requested account is honoured while it is healthy, because callers use it
// for session affinity: one account is one egress, and switching egress pads the
// upstream's prompt cache. Failover only happens when it is not healthy.
func (r *Reverse) choose(requested string, h http.Header) (pool.Route, string) {
	if requested != "" && requested != "auto" {
		for _, s := range r.Pool.Snapshots() {
			if s.Lease == requested && s.State != pool.StateBlocked {
				return s.Route, requested
			}
		}
	}
	// Callers may pin a route explicitly for testing.
	if pinned := h.Get("X-Egress-Pin"); pinned != "" {
		for _, s := range r.Pool.Snapshots() {
			if s.Lease == pinned && s.State != pool.StateBlocked {
				return s.Route, pinned
			}
		}
	}
	route, ok := r.Pool.Pick()
	if !ok {
		return pool.Route{}, ""
	}
	return route, route.Lease
}

// observe records passive evidence from a live request.
//
// This is the only source of evidence when active probing is off, so it has to
// reuse the same classifier the prober uses. Writing a second interpretation
// here is how the two paths drift apart and start disagreeing about a route.
//
// A 403 is recorded only when its body says the egress is blocked. An
// unreadable or unrecognised 403 stays silent: the same status also covers a
// malformed request, and condemning a route on that would drain the pool.
func (r *Reverse) observe(key string, status int, encoding string, prefix []byte, latency time.Duration, streamErr error) {
	if status >= 200 && status < 300 {
		r.Pool.Record(key, pool.VerdictOK, latency, "served live traffic")
		return
	}

	if status == http.StatusForbidden {
		body := probe.Decode(prefix, encoding)
		res := probe.Classify(status, body, latency)
		if res.Verdict == pool.VerdictBlocked {
			r.Pool.Record(key, pool.VerdictBlocked, latency, res.Detail)
			r.Log.Info("egress blocked by live traffic", "route", key, "detail", res.Detail)
			if r.Evictor != nil {
				r.Evictor.Evict(key)
			}
			return
		}
		// bad_request or unclassified: not evidence about the egress.
		return
	}

	if status == http.StatusBadRequest {
		// The egress carried the request; the upstream rejected its content
		// (context length, malformed body).
		r.Pool.Record(key, pool.VerdictBadRequest, latency, "upstream rejected request content")
		return
	}

	if status >= 500 {
		// Upstream-side failure: says nothing about the egress.
		return
	}

	if streamErr != nil {
		r.Pool.Record(key, pool.VerdictUnknown, latency, "stream error: "+streamErr.Error())
	}
}

type capWriter struct {
	buf   *bytes.Buffer
	limit int64
	n     int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.n < c.limit {
		take := int64(len(p))
		if remain := c.limit - c.n; take > remain {
			take = remain
		}
		c.buf.Write(p[:take])
		c.n += take
	}
	return len(p), nil
}

// flushWriter flushes after every write so SSE chunks leave immediately.
type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

func splitIdentity(id string) (platform, account string, ok bool) {
	i := strings.IndexByte(id, '.')
	if i <= 0 || i == len(id)-1 {
		return "", "", false
	}
	return id[:i], id[i+1:], true
}

// hopByHop are connection-scoped headers that must not be forwarded.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(k string) bool {
	for _, h := range hopByHop {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return false
}

// DeleteBlocked removes the lease binding for a route that live traffic has
// proved blocked, so Resin re-allocates it on a different node.
//
// It is unused by the passive path, which evicts one account at a time through
// the scheduler; it stays for operators who want to sweep a whole pool by hand.
func DeleteBlocked(ctx context.Context, c *resin.Client, platformID string, routes []pool.Snapshot, log *slog.Logger) {
	for _, s := range routes {
		if s.State != pool.StateBlocked {
			continue
		}
		// Only evict on positive evidence of a blocked egress. A route that is
		// merely unreachable may be a transient network problem, and evicting it
		// would churn the pool for nothing.
		if s.LastVerdict != pool.VerdictBlocked {
			continue
		}
		if err := c.DeleteLease(ctx, platformID, s.Lease); err != nil {
			log.Warn("delete lease failed", "account", s.Lease, "error", err)
			continue
		}
		log.Info("evicted blocked lease", "account", s.Lease, "egress", s.EgressIP, "detail", s.LastDetail)
	}
}
