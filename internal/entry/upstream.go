package entry

import (
	"strings"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// Upstream is one Resin instance the pool draws leases from.
//
// Several may be configured. A lease belongs to exactly one Resin, so the only
// thing a caller has to know is the lease name: the entry resolves the owner
// from the route and dials that instance with that instance's own password.
// Keeping the password per instance is what makes adding a second Resin a
// configuration change rather than a code change.
type Upstream struct {
	// Name identifies the instance in configuration and in a route's Upstream.
	Name string
	// ProxyAddr is the host:port of the Resin SOCKS5 listener.
	ProxyAddr string
	// Token is this instance's Resin password. It authenticates the hop from
	// this entry to Resin, not the client: the entry has its own Password.
	Token string
	// BaseURL is the http:// endpoint of the same instance, for the reverse
	// entry.
	BaseURL string
}

// Upstreams is the registry entries resolve a route's owner against.
type Upstreams map[string]Upstream

// Resolve returns the upstream a route belongs to. An empty or unknown name
// falls back to the default instance so a single-Resin deployment keeps
// working without the caller having to name anything.
func (u Upstreams) Resolve(name string) (Upstream, bool) {
	if name != "" {
		if up, ok := u[name]; ok {
			return up, true
		}
	}
	if up, ok := u[DefaultUpstream]; ok {
		return up, true
	}
	if len(u) == 1 {
		for _, up := range u {
			return up, true
		}
	}
	return Upstream{}, false
}

// DefaultUpstream names the instance used when a caller does not name one.
const DefaultUpstream = "default"

// splitPreferred reads a proxy username. Resin's own format is
// "<platform>.<account>"; a leading "<upstream>/" pins one instance, which a
// client needs when several instances hold an account of the same name. The
// slash is safe because Resin names never contain one.
func splitPreferred(username string) (upstream, lease string) {
	u := strings.TrimSpace(username)
	if i := strings.IndexByte(u, '/'); i > 0 {
		upstream, u = u[:i], u[i+1:]
	}
	return upstream, normalisePreferred(u)
}

// PinRoute turns a client's proxy username into the route it names.
//
// Resin creates a lease the first time it is used, so a name a caller just
// configured is legitimate before any discovery pass has listed it. Treating
// discovery as the authority would reject exactly those names, which is
// backwards: the caller decides which lease to use, discovery only reports what
// already exists.
func PinRoute(ups Upstreams, username string) (pool.Route, bool) {
	upstream, lease := splitPreferred(username)
	if lease == "" || lease == "auto" {
		return pool.Route{}, false
	}
	multi := len(ups) > 1
	if upstream == "" {
		if multi {
			upstream = DefaultUpstream
		} else {
			upstream = ups.singleName()
		}
	}
	key := lease
	if multi {
		key = upstream + "/" + lease
	}
	return pool.Route{Key: key, Lease: lease, Upstream: upstream}, true
}

// singleName is the only configured instance's name, or the default when the
// registry is empty.
func (u Upstreams) singleName() string {
	for name := range u {
		return name
	}
	return DefaultUpstream
}

// Names returns the configured instance names, sorted for stable output.
func (u Upstreams) Names() []string {
	out := make([]string, 0, len(u))
	for k := range u {
		out = append(out, k)
	}
	// Small maps: an insertion sort keeps this dependency-free.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && strings.Compare(out[j], out[j-1]) < 0; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
