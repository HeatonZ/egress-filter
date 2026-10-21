package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
	"github.com/HeatonZ/egress-filter/internal/resin"
)

// fakeResin serves the two control-plane calls the scheduler makes.
type fakeResin struct {
	srv     *httptest.Server
	leases  map[string][]resin.Lease // platform id -> leases
	deletes []string                 // "platform/account"
	tokens  map[string]string        // platform id -> bearer token seen
}

func newFakeResin(t *testing.T) *fakeResin {
	t.Helper()
	f := &fakeResin{leases: map[string][]resin.Lease{}, tokens: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/api/v1/platforms/"
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		parts := strings.Split(rest, "/")
		if len(parts) < 2 || parts[1] != "leases" {
			http.NotFound(w, r)
			return
		}
		platform := parts[0]
		f.tokens[platform] = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": f.leases[platform],
				"total": len(f.leases[platform]),
			})
		case http.MethodDelete:
			account := ""
			if len(parts) >= 3 {
				account = parts[2]
			}
			f.deletes = append(f.deletes, platform+"/"+account)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newPool() *pool.Pool {
	return pool.New(pool.Options{FailThreshold: 5, RecoverThreshold: 1})
}

// Two Resin instances must both be discovered, and each route must remember
// which instance owns it: the data path has no other way to pick the right
// password when it dials.
func TestDiscoverFansOutAcrossInstances(t *testing.T) {
	f := newFakeResin(t)
	f.leases["p1"] = []resin.Lease{{PlatformID: "p1", Account: "leaseA", EgressIP: "1.1.1.1"}}
	f.leases["p2"] = []resin.Lease{{PlatformID: "p2", Account: "leaseB", EgressIP: "2.2.2.2"}}

	p := newPool()
	s := New(p, nil, Config{Platform: "opencode"}, quiet())
	s.Sources = []Source{
		{Name: "a", Client: resin.New(f.srv.URL, "ta"), PlatformID: "p1"},
		{Name: "b", Client: resin.New(f.srv.URL, "tb"), PlatformID: "p2"},
	}

	s.discover(context.Background())

	snaps := p.Snapshots()
	if len(snaps) != 2 {
		t.Fatalf("routes = %d, want 2: %+v", len(snaps), snaps)
	}
	byKey := map[string]pool.Snapshot{}
	for _, sn := range snaps {
		byKey[sn.Key] = sn
	}
	for key, upstream := range map[string]string{"a/leaseA": "a", "b/leaseB": "b"} {
		sn, ok := byKey[key]
		if !ok {
			t.Fatalf("route %q missing, got %v", key, keysOf(snaps))
		}
		if sn.Upstream != upstream {
			t.Fatalf("route %q upstream = %q, want %q", key, sn.Upstream, upstream)
		}
		if sn.Lease == "" {
			t.Fatalf("route %q lost its lease name", key)
		}
	}
	if f.tokens["p1"] != "ta" || f.tokens["p2"] != "tb" {
		t.Fatalf("each instance must be read with its own token, saw %v", f.tokens)
	}
}

// One instance keeps the historical bare-account key so existing status output
// and eviction cooldowns do not change.
func TestDiscoverSingleInstanceKeepsBareKey(t *testing.T) {
	f := newFakeResin(t)
	f.leases["p1"] = []resin.Lease{{Account: "leaseA", EgressIP: "1.1.1.1"}}
	p := newPool()
	s := New(p, resin.New(f.srv.URL, "ta"), Config{PlatformID: "p1", Platform: "opencode"}, quiet())
	s.discover(context.Background())
	snaps := p.Snapshots()
	if len(snaps) != 1 || snaps[0].Key != "leaseA" {
		t.Fatalf("routes = %+v, want one bare leaseA", snaps)
	}
}

// Eviction must reach the instance that owns the route, with that instance's
// token and the bare lease name.
func TestEvictUsesOwningInstance(t *testing.T) {
	f := newFakeResin(t)
	f.leases["p1"] = []resin.Lease{{Account: "leaseA"}}
	f.leases["p2"] = []resin.Lease{{Account: "leaseB"}}

	p := newPool()
	s := New(p, nil, Config{
		Platform:      "opencode",
		Evict:         true,
		EvictCooldown: time.Minute,
	}, quiet())
	s.Sources = []Source{
		{Name: "a", Client: resin.New(f.srv.URL, "ta"), PlatformID: "p1"},
		{Name: "b", Client: resin.New(f.srv.URL, "tb"), PlatformID: "p2"},
	}
	s.discover(context.Background())
	// Eviction only applies to a route live traffic has already withdrawn.
	for i := 0; i < 5; i++ {
		p.Record("b/leaseB", pool.VerdictBlocked, 0, "blocked")
	}

	s.evict(context.Background(), "b/leaseB")

	if len(f.deletes) != 1 || f.deletes[0] != "p2/leaseB" {
		t.Fatalf("deletes = %v, want [p2/leaseB]", f.deletes)
	}
	if f.tokens["p2"] != "tb" {
		t.Fatalf("delete used token %q, want tb", f.tokens["p2"])
	}
	if s.Evicted() != 1 {
		t.Fatalf("evicted = %d, want 1", s.Evicted())
	}
}

// A lease re-allocated onto a new node is a fresh egress: the old verdict must
// not follow it, or the route stays blocked forever with no probe to clear it.
func TestDiscoverResetsHealthWhenEgressChanges(t *testing.T) {
	f := newFakeResin(t)
	f.leases["p1"] = []resin.Lease{{Account: "leaseA", EgressIP: "1.1.1.1"}}
	p := newPool()
	s := New(p, resin.New(f.srv.URL, "ta"), Config{PlatformID: "p1", Platform: "opencode"}, quiet())

	s.discover(context.Background())
	for i := 0; i < 5; i++ {
		p.Record("leaseA", pool.VerdictBlocked, 0, "blocked")
	}
	if !p.Blocked("leaseA") {
		t.Fatalf("setup: leaseA should be blocked")
	}

	f.leases["p1"] = []resin.Lease{{Account: "leaseA", EgressIP: "9.9.9.9"}}
	s.discover(context.Background())

	if p.Blocked("leaseA") {
		t.Fatal("leaseA stayed blocked after its egress changed")
	}
}

func keysOf(snaps []pool.Snapshot) []string {
	out := make([]string, 0, len(snaps))
	for _, sn := range snaps {
		out = append(out, sn.Key)
	}
	return out
}
