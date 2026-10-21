package pool

import (
	"testing"
	"time"
)

// A lease a client names exists as far as Resin is concerned: Resin creates it
// on first use. Discovery must not be able to delete it out from under a caller
// that keeps asking for it, or the failure streak toward eviction restarts on
// every refresh.
func TestEnsureSurvivesSync(t *testing.T) {
	p := New(Options{})
	p.Sync([]Route{{Key: "leaseA", Lease: "leaseA"}})

	p.Ensure(Route{Key: "fresh", Lease: "fresh"})
	if _, ok := p.Pick(); !ok {
		t.Fatal("pool has no route")
	}

	// A discovery pass that has not caught up yet must keep the client's route.
	p.Sync([]Route{{Key: "leaseA", Lease: "leaseA"}})
	var found bool
	for _, s := range p.Snapshots() {
		if s.Key == "fresh" {
			found = true
		}
	}
	if !found {
		t.Fatal("a client-named route was dropped by a discovery refresh")
	}

	// Once discovery lists it, it is an ordinary route and can be dropped again
	// when the lease really disappears.
	p.Sync([]Route{{Key: "fresh", Lease: "fresh"}})
	p.Sync(nil)
	if len(p.Snapshots()) != 0 {
		t.Fatalf("routes survived a discovery pass that listed none: %+v", p.Snapshots())
	}
}

// A client-named route must keep its failure streak across refreshes, or the
// threshold toward eviction is never reached.
func TestEnsureKeepsFailureStreak(t *testing.T) {
	p := New(Options{FailThreshold: 5})
	p.Ensure(Route{Key: "fresh", Lease: "fresh"})
	for i := 0; i < 3; i++ {
		p.Record("fresh", VerdictBlocked, 0, "blocked")
	}
	p.Sync(nil)
	for i := 0; i < 2; i++ {
		p.Record("fresh", VerdictBlocked, 0, "blocked")
	}
	if !p.Blocked("fresh") {
		t.Fatalf("state = %v after 5 blocked verdicts across a refresh, want blocked",
			snapshotKey(p, "fresh").State)
	}
}

// Ensure must not resurrect a blocked route: the block is positive evidence and
// outranks the caller's wish.
func TestEnsureDoesNotClearBlocked(t *testing.T) {
	p := New(Options{FailThreshold: 2})
	p.Ensure(Route{Key: "fresh", Lease: "fresh"})
	p.Record("fresh", VerdictBlocked, 0, "blocked")
	p.Record("fresh", VerdictBlocked, 0, "blocked")
	if !p.Blocked("fresh") {
		t.Fatal("setup: route should be blocked")
	}
	p.Ensure(Route{Key: "fresh", Lease: "fresh"})
	if !p.Blocked("fresh") {
		t.Fatal("Ensure cleared a blocked route")
	}
}

func snapshotKey(p *Pool, key string) Snapshot {
	for _, s := range p.Snapshots() {
		if s.Key == key {
			return s
		}
	}
	return Snapshot{}
}

// A client-named route that discovery never adopts must expire, or a single
// mistyped lease would sit in the pool and in /status forever.
func TestEnsureExpiresAfterIdle(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{LazyTTL: 10 * time.Minute, Now: func() time.Time { return now }})

	p.Ensure(Route{Key: "typo", Lease: "typo"})
	now = now.Add(9 * time.Minute)
	p.Sync(nil)
	if len(p.Snapshots()) != 1 {
		t.Fatal("route expired before its TTL")
	}

	now = now.Add(2 * time.Minute)
	p.Sync(nil)
	if len(p.Snapshots()) != 0 {
		t.Fatalf("idle client-named route survived its TTL: %+v", p.Snapshots())
	}
}

// Being named again refreshes the idle clock: a lease in active use must not
// expire just because discovery has not listed it yet.
func TestEnsureRefreshesIdleClock(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{LazyTTL: 10 * time.Minute, Now: func() time.Time { return now }})

	p.Ensure(Route{Key: "busy", Lease: "busy"})
	now = now.Add(9 * time.Minute)
	p.Ensure(Route{Key: "busy", Lease: "busy"})
	now = now.Add(9 * time.Minute)
	p.Sync(nil)
	if len(p.Snapshots()) != 1 {
		t.Fatal("a route still in use expired")
	}
}
