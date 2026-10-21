// Package probe decides whether an egress can actually serve the upstream
// business, by replaying the real client request through it.
//
// Why not a plain GET: the upstream answers 200 to any egress for a bare
// request, so a connectivity check cannot tell a working egress from a blocked
// one. The gate only engages when the request carries the client identity it
// expects, which is exactly what this package reproduces.
package probe

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// ClientIdentity is the request shape the upstream gate accepts.
//
// The description text below is a hard requirement, not a comment: truncating
// it drops the request back to the generic-client rejection. Keep it verbatim.
type ClientIdentity struct {
	UserAgent     string
	ClientHeader  string
	ProjectHeader string
	Model         string
	Path          string
	ToolDesc      string
}

// DefaultIdentity reproduces an OpenCode CLI request.
//
// Every value here was copied from a captured successful request rather than
// inferred. The upstream inspects the request shape closely enough that a
// near-miss is rejected with "can only be used from within OpenCode", which
// looks like an egress problem but is not.
func DefaultIdentity() ClientIdentity {
	return ClientIdentity{
		UserAgent:     "opencode/latest/2.0.32/cli",
		ClientHeader:  "cli",
		ProjectHeader: "global",
		Model:         "big-pickle",
		Path:          "/inference/v1/chat/completions",
		ToolDesc: `Read the contents of a file or directory. Supports text files, images, and PDFs. ` +
			`Images and PDFs are presented directly to the model. Each text line is prefixed by its ` +
			`1-based line number as <line>: <content>. The prefix is for reference and is not part of ` +
			`the file content. Directory entries are returned one per line. Use offset and limit to ` +
			`read large files or directories in sections. Prefer one larger read over many small ` +
			`slices, and use grep to find specific content in large files.`,
	}
}

// SessionID derives a stable session id per route.
//
// The shape matches what the client emits: "ses_" followed by 12 hex characters
// and 14 base62 ones. A value of the wrong length or alphabet is rejected before
// the request ever reaches the egress, which would make every route look broken.
func SessionID(key string, now time.Time) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var tail [14]byte
	v := h
	for i := 13; i >= 0; i-- {
		tail[i] = base62[v%62]
		v /= 62
	}
	// The hex half carries the timestamp so ids look time-ordered, like the
	// client's own.
	return fmt.Sprintf("ses_%012x%s", uint64(now.UnixMilli())&0xFFFFFFFFFFFF, tail)
}

// Body builds the JSON request body.
//
// The byte layout mirrors a captured request: field order, integer types and
// the trailing "strict" flag all match. It is written by hand instead of via
// encoding/json because Go's struct order would emit offsets as numbers in a
// different position, and the gate is sensitive to the shape it receives.
func (id ClientIdentity) Body(sessionID string) []byte {
	return []byte(`{"model":"` + id.Model + `","messages":[{"role":"user","content":"hi"}],"max_tokens":1,` +
		`"tools":[{"type":"function","function":{"name":"read","description":"` + id.ToolDesc + `",` +
		`"parameters":{"type":"object","properties":{` +
		`"path":{"type":"string","description":"File or directory to read"},` +
		`"offset":{"type":"integer","minimum":0,"description":"The line or directory entry to start reading from (1-based)"},` +
		`"limit":{"type":"integer","minimum":0,"description":"The maximum number of lines or directory entries to read (defaults to and capped at 2000)"}` +
		`},"required":["path"],"additionalProperties":false},"strict":false}}],` +
		`"stream":true,"stream_options":{"include_usage":true}}`)
}

// Request is one probe against one route.
type Request struct {
	// BaseURL is the reverse-proxy base the request goes through, without a
	// trailing slash. Empty means "use the forward proxy".
	BaseURL string
	// ProxyFunc returns the SOCKS5 address for forward mode.
	ProxyFunc func() (*url.URL, bool)
}

// Result is the outcome of one probe.
type Result struct {
	Verdict pool.Verdict
	Status  int
	Detail  string
	Latency time.Duration
	// Body is kept only when it explains a verdict, truncated hard.
	Body string
}

// Prober replays the business request through a route.
type Prober struct {
	Identity ClientIdentity
	Timeout  time.Duration
	// MaxBody caps how much of the response body is read for classification.
	MaxBody int64
}

// NewProber returns a prober with sane defaults.
func NewProber() *Prober {
	return &Prober{
		Identity: DefaultIdentity(),
		Timeout:  25 * time.Second,
		MaxBody:  64 << 10,
	}
}

// Probe sends the business request through the route and classifies the answer.
func (p *Prober) Probe(ctx context.Context, route pool.Route, baseURL string, proxyURL *url.URL) Result {
	sessionID := SessionID(route.Key, time.Now())
	body := p.Identity.Body(sessionID)

	target := baseURL
	if target == "" {
		target = "https://opencode.ai"
	}
	reqURL := strings.TrimRight(target, "/") + p.Identity.Path

	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return Result{Verdict: pool.VerdictUnknown, Detail: "build request: " + err.Error()}
	}

	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "*")
	req.Header.Set("Authorization", "Bearer public")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("User-Agent", p.Identity.UserAgent)
	req.Header.Set("X-Opencode-Client", p.Identity.ClientHeader)
	req.Header.Set("X-Opencode-Project", p.Identity.ProjectHeader)
	req.Header.Set("X-Opencode-Session", sessionID)
	req.Header.Set("X-Opencode-Session-Id", sessionID)
	req.Header.Set("X-Session-Affinity", sessionID)
	req.Header.Set("X-Session-Id", sessionID)

	transport := &http.Transport{
		// The body is already encoded by us; letting Go add another layer would
		// make the classification below read the wrong bytes.
		DisableCompression:  true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	} else {
		transport.Proxy = nil
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return Result{Verdict: pool.VerdictUnknown, Detail: err.Error(), Latency: latency}
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, p.MaxBody))
	text := decode(raw, resp.Header.Get("Content-Encoding"))

	return classify(resp.StatusCode, text, latency)
}

// decode inflates the body when the server compressed it.
//
// Classification matches on text, and gzip bytes never contain the marker. This
// is the single most common reason a "the upstream is fine" conclusion is
// wrong: the body was compressed and the search silently matched nothing.
func decode(raw []byte, encoding string) string {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	var r io.Reader = bytes.NewReader(raw)
	switch {
	case strings.Contains(enc, "gzip"):
		zr, err := gzip.NewReader(r)
		if err != nil {
			return string(raw)
		}
		defer zr.Close()
		r = zr
	case strings.Contains(enc, "deflate"):
		if zr, err := zlib.NewReader(r); err == nil {
			defer zr.Close()
			r = zr
		} else if fr := flate.NewReader(r); fr != nil {
			defer fr.Close()
			r = fr
		}
	}
	out, err := io.ReadAll(io.LimitReader(r, 64<<10))
	// A truncated capture (the prefix cut mid-stream) makes the inflated read
	// end with an error, but everything decoded before that point is still
	// valid — and that prefix is exactly what carries the error text. Dropping
	// it here is how a blocked 403 ends up looking like an unrecognised one.
	if len(out) > 0 {
		return string(out)
	}
	if err != nil {
		return string(raw)
	}
	return ""
}

// classify turns a status + body into a verdict.
//
// The two 403 families are the crux: "blocked egress" condemns the route,
// "wrong request shape" condemns the configuration. Treating them alike is what
// makes a pool either churn endlessly or never clean up.
func classify(status int, body string, latency time.Duration) Result {
	lower := strings.ToLower(body)
	res := Result{Status: status, Latency: latency, Body: truncate(body, 300)}

	switch {
	case status >= 200 && status < 300:
		res.Verdict = pool.VerdictOK
		res.Detail = "served"
		return res

	case status == http.StatusForbidden:
		switch {
		case strings.Contains(lower, "abusive traffic"):
			res.Verdict = pool.VerdictBlocked
			res.Detail = "egress blocked: abusive traffic"
		case strings.Contains(lower, "available from your current network"),
			strings.Contains(lower, "arent available from your current network"),
			strings.Contains(lower, "aren't available from your current network"):
			res.Verdict = pool.VerdictBlocked
			res.Detail = "egress blocked: free tier network restriction"
		case strings.Contains(lower, "can only be used from within"):
			res.Verdict = pool.VerdictBadRequest
			res.Detail = "request shape rejected (configuration, not the egress)"
		default:
			// Unknown 403: do not condemn the route on a message we do not
			// recognise, but do not call it healthy either.
			res.Verdict = pool.VerdictUnknown
			res.Detail = "unclassified 403"
		}
		return res

	case status == http.StatusBadRequest:
		// A 400 is the upstream rejecting the request content (context length,
		// malformed body). The egress carried it fine.
		res.Verdict = pool.VerdictBadRequest
		res.Detail = "upstream rejected request content"
		return res

	case status == http.StatusTooManyRequests:
		// Rate limiting is a capacity signal, not a blocked egress. Condemning
		// the route here would drain the pool during busy periods.
		res.Verdict = pool.VerdictUnknown
		res.Detail = "rate limited"
		return res
	}

	res.Verdict = pool.VerdictUnknown
	res.Detail = fmt.Sprintf("upstream status %d", status)
	return res
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Classify exposes the verdict mapping for callers that observe real traffic
// instead of sending their own probe. Passive and active paths must agree on
// what a response means, or the pool's state depends on who looked last.
func Classify(status int, body string, latency time.Duration) Result {
	return classify(status, body, latency)
}

// Decode exposes body decompression for the same reason: a passive observer
// captures whatever bytes the upstream sent, which is usually compressed.
func Decode(raw []byte, encoding string) string { return decode(raw, encoding) }

// Ready reports whether the verdict means the route is usable.
func Ready(v pool.Verdict) bool {
	return v == pool.VerdictOK || v == pool.VerdictBadRequest
}
