// Package pool tracks the health of egress routes.
//
// A route is one way of reaching the upstream: a resin lease reached through
// the reverse-proxy path, or a SOCKS5 entry reached through resin's forward
// proxy. The pool answers exactly one question for both entry points — which
// routes are usable right now — so the health logic lives here once instead of
// being duplicated per protocol.
package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Verdict is what a completed request says about a route.
//
// Three values, not two. The upstream answers 403 for two unrelated reasons —
// a blocked egress and a request that does not look like the real client — and
// a two-valued model forces one of them into the wrong bucket. "No evidence"
// keeps the route's state untouched.
type Verdict int

const (
	// VerdictUnknown means the request never reached the upstream far enough to
	// say anything (dial failure, timeout, TLS error).
	VerdictUnknown Verdict = iota
	// VerdictOK means the upstream served the request.
	VerdictOK
	// VerdictBlocked means the upstream refused this egress specifically.
	VerdictBlocked
	// VerdictBadRequest means the request shape was rejected.
	VerdictBadRequest
	// VerdictServerError means the upstream answered non-2xx (5xx, 429, an
	// unclassified 403). It counts like any other failure.
	VerdictServerError
	// VerdictTimeout means the route did not deliver a response in time.
	VerdictTimeout
)

func (v Verdict) String() string {
	switch v {
	case VerdictOK:
		return "ok"
	case VerdictBlocked:
		return "blocked"
	case VerdictBadRequest:
		return "bad_request"
	case VerdictServerError:
		return "server_error"
	case VerdictTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// State is a route's current health.
type State int

const (
	// StateReady: usable.
	StateReady State = iota
	// StateSuspect: failed recently, still serving but on probation.
	StateSuspect
	// StateBlocked: refused; not offered to callers.
	StateBlocked
)

func (s State) String() string {
	switch s {
	case StateReady:
		return "ready"
	case StateSuspect:
		return "suspect"
	case StateBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// Route is one egress path.
type Route struct {
	// Key uniquely identifies the route, e.g. the resin account name.
	Key string
	// Lease is the resin account used in the reverse-proxy path.
	Lease string
	// EgressIP is the last observed public address, for operators reading logs.
	EgressIP string
	// ProxyURL is the SOCKS5 endpoint for forward-proxy callers.
	ProxyURL string
	// Upstream names the Resin instance this lease belongs to, so an entry can
	// dial the right instance with that instance's own password.
	Upstream string
}

// Snapshot is a read-only copy of a route's health, safe to hand to callers.
type Snapshot struct {
	Route
	State        State
	ConsecOK     int
	ConsecFail   int
	LastVerdict  Verdict
	LastError    string
	LastProbeAt  time.Time
	LastOKAt     time.Time
	LastDetail   string
	ProbeLatency time.Duration
}

// Options tunes the state machine.
type Options struct {
	// FailThreshold is how many consecutive failures withdraw a route. Any
	// success resets the streak: a route that still serves traffic is not
	// blocked, however many failures it had before.
	FailThreshold int
	// RecoverThreshold is how many consecutive successes return a blocked
	// route to ready.
	RecoverThreshold int
	// ProbeInterval is how often each route is probed. Only used by active
	// probing; passive mode leaves it unused.
	ProbeInterval time.Duration
	// LazyTTL is how long a route a client named keeps existing after its last
	// use, while discovery still does not list it. Without an expiry a one-off
	// typo would stay in the pool and in /status forever.
	LazyTTL time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.FailThreshold <= 0 {
		o.FailThreshold = 5
	}
	if o.RecoverThreshold <= 0 {
		o.RecoverThreshold = 2
	}
	if o.ProbeInterval <= 0 {
		o.ProbeInterval = 60 * time.Second
	}
	if o.LazyTTL <= 0 {
		o.LazyTTL = 10 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

type entry struct {
	route Route

	state      State
	consecOK   int
	consecFail int

	lastVerdict  Verdict
	lastError    string
	lastDetail   string
	lastProbeAt  time.Time
	lastOKAt     time.Time
	probeLatency time.Duration
	// lastEvictAt records the last time this route's lease was deleted, so a
	// single noisy window cannot trigger repeated deletions.
	lastEvictAt time.Time
	// lazy marks a route a client named before discovery listed it. Resin
	// creates a lease on first use, so such a route is real even though the
	// last discovery pass did not know it yet.
	lazy bool
	// lastUsed is when a client last named this route, used to expire one that
	// discovery never adopts.
	lastUsed time.Time
}

// Pool is the shared route registry.
type Pool struct {
	mu      sync.RWMutex
	opts    Options
	entries map[string]*entry
	// order preserves insertion order so callers get a stable rotation instead
	// of Go's randomised map iteration.
	order []string
}

// New creates an empty pool.
func New(opts Options) *Pool {
	return &Pool{
		opts:    opts.withDefaults(),
		entries: make(map[string]*entry),
	}
}

// Options returns the effective options.
func (p *Pool) Options() Options { return p.opts }

// Ensure returns the route for a lease a client named, creating it when
// discovery has not seen it.
//
// The client is the authority on which lease to use: Resin creates the lease on
// demand, so requiring a discovery pass first would reject exactly the accounts
// a caller just configured. A created route starts ready for the same reason
// discovered ones do — with passive observation nothing else would ever make it
// usable.
func (p *Pool) Ensure(r Route) Route {
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.entries[r.Key]; ok {
		e.lastUsed = p.opts.Now()
		return e.route
	}
	e := &entry{route: r, state: StateReady, lazy: true, lastUsed: p.opts.Now()}
	p.entries[r.Key] = e
	p.order = append(p.order, r.Key)
	return r
}

// Sync replaces the route set with routes, preserving the health of routes that
// already exist. A route that disappears from routes is dropped along with its
// history: it no longer exists upstream, so remembering it would only delay the
// next probe cycle.
func (p *Pool) Sync(routes []Route) {
	p.mu.Lock()
	defer p.mu.Unlock()

	seen := make(map[string]struct{}, len(routes))
	order := make([]string, 0, len(routes))
	for _, r := range routes {
		if r.Key == "" {
			continue
		}
		if _, dup := seen[r.Key]; dup {
			continue
		}
		seen[r.Key] = struct{}{}
		order = append(order, r.Key)

		e, ok := p.entries[r.Key]
		if !ok {
			// Optimistic start. With passive-only observation there is no probe
			// to establish health, so a route must be usable until traffic says
			// otherwise; starting it "suspect" would leave every route
			// unselectable forever.
			e = &entry{state: StateReady}
			p.entries[r.Key] = e
		}
		// Identity fields follow the current discovery result; health fields
		// stay with the route. Seeing it upstream makes it a discovered route.
		e.route = r
		e.lazy = false
	}
	// A route a client pinned keeps its place until discovery lists it. Dropping
	// it here would make the next request recreate it from scratch and lose the
	// failure streak we were counting toward eviction.
	for _, key := range p.order {
		if _, ok := seen[key]; ok {
			continue
		}
		if e, ok := p.entries[key]; ok && e.lazy &&
			p.opts.Now().Sub(e.lastUsed) < p.opts.LazyTTL {
			order = append(order, key)
		}
	}
	for key, e := range p.entries {
		if _, ok := seen[key]; ok {
			continue
		}
		// Routes that were adopted by discovery and now vanished are genuinely
		// gone. A lazy one only exists because a client named it, so it expires
		// once nobody has asked for it for a while.
		if e.lazy && p.opts.Now().Sub(e.lastUsed) < p.opts.LazyTTL {
			continue
		}
		delete(p.entries, key)
	}
	p.order = order
}

// Record applies one probe or passive observation.
func (p *Pool) Record(key string, v Verdict, latency time.Duration, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, ok := p.entries[key]
	if !ok {
		return
	}
	now := p.opts.Now()
	e.lastProbeAt = now
	e.lastVerdict = v
	e.lastDetail = detail
	e.probeLatency = latency

	switch v {
	case VerdictOK:
		e.consecOK++
		e.consecFail = 0
		e.lastOKAt = now
		e.lastError = ""
		// A success ends the failure streak. Only a route that keeps failing
		// without ever serving is withdrawn.
		if e.state == StateBlocked && e.consecOK >= p.opts.RecoverThreshold {
			e.state = StateReady
		} else if e.state == StateSuspect && e.consecOK >= 1 {
			e.state = StateReady
		}

	default:
		// Every other verdict is a failure: the route did not serve the request.
		// 4xx, 5xx, timeout and dial failure stay distinguishable in lastDetail
		// for operators, but the count does not care — five in a row withdraws
		// the route whatever produced them.
		e.consecFail++
		e.consecOK = 0
		if e.consecFail >= p.opts.FailThreshold {
			e.state = StateBlocked
		} else {
			e.state = StateSuspect
		}
	}
}

// IsTimeout reports whether err is a deadline rather than a refusal, so callers
// can tell a stalled egress apart from one that rejected the connection.
func IsTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// Blocked reports whether the route has been withdrawn from selection.
func (p *Pool) Blocked(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[key]
	return ok && e.state == StateBlocked
}

// ClaimEviction reserves the right to delete this route's lease.
//
// Any withdrawn route is evictable, whatever produced the failures: a route
// that reached the threshold is not serving, and the only way back is a fresh
// lease. The cooldown stops the same account being deleted repeatedly inside
// one window. Reserving before the delete keeps concurrent requests from all
// firing the same eviction.
func (p *Pool) ClaimEviction(key string, cooldown time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, ok := p.entries[key]
	if !ok {
		return false
	}
	if e.state != StateBlocked {
		return false
	}
	now := p.opts.Now()
	if !e.lastEvictAt.IsZero() && now.Sub(e.lastEvictAt) < cooldown {
		return false
	}
	e.lastEvictAt = now
	return true
}

// ReleaseEviction puts the cooldown back after a failed delete, so a transient
// control-plane error does not silence eviction for the whole cooldown window.
func (p *Pool) ReleaseEviction(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[key]; ok {
		e.lastEvictAt = time.Time{}
	}
}

// Reset clears a route's health so the next observation starts clean. Used when
// a lease has been re-allocated: the account keeps its name but the egress
// behind it is now a different node, so the old verdict no longer applies.
func (p *Pool) Reset(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[key]; ok {
		e.state = StateReady
		e.consecOK = 0
		e.consecFail = 0
		e.lastVerdict = VerdictUnknown
		e.lastDetail = ""
		e.lastError = ""
	}
}

// SetError attaches the last transport error to a route for operator display.
func (p *Pool) SetError(key, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[key]; ok {
		e.lastError = msg
	}
}

// Pick returns the best ready route, rotating so a hot route does not take
// every request. It returns false when no route is ready.
func (p *Pool) Pick() (Route, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	best := -1
	bestScore := -1
	for i, key := range p.order {
		e := p.entries[key]
		// Suspect routes stay selectable on purpose. Under passive observation
		// nothing probes a route back to health, so treating one failure as
		// "do not use" would retire an egress permanently — and with a free tier
		// that answers a stray 403 under load, that would be most of the pool.
		// Only a route with positive evidence of a block is withheld.
		if e == nil || e.state == StateBlocked {
			continue
		}
		// Prefer more consecutive successes, then earlier position. A suspect
		// route therefore loses to healthy ones without being excluded.
		score := e.consecOK
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return Route{}, false
	}
	r := p.entries[p.order[best]].route
	// Rotate: move the chosen key to the back so the next call starts after it.
	key := p.order[best]
	copy(p.order[best:], p.order[best+1:])
	p.order[len(p.order)-1] = key
	return r, true
}

// Snapshots returns a copy of every route's health.
func (p *Pool) Snapshots() []Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]Snapshot, 0, len(p.order))
	for _, key := range p.order {
		e := p.entries[key]
		if e == nil {
			continue
		}
		out = append(out, Snapshot{
			Route:        e.route,
			State:        e.state,
			ConsecOK:     e.consecOK,
			ConsecFail:   e.consecFail,
			LastVerdict:  e.lastVerdict,
			LastError:    e.lastError,
			LastProbeAt:  e.lastProbeAt,
			LastOKAt:     e.lastOKAt,
			LastDetail:   e.lastDetail,
			ProbeLatency: e.probeLatency,
		})
	}
	return out
}

// Counts summarises the pool for the status endpoint.
func (p *Pool) Counts() map[string]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := map[string]int{"ready": 0, "suspect": 0, "blocked": 0, "total": len(p.order)}
	for _, key := range p.order {
		if e := p.entries[key]; e != nil {
			out[e.state.String()]++
		}
	}
	return out
}
