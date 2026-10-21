package pool

import (
	"testing"
	"time"
)

func testPool() *Pool {
	return New(Options{FailThreshold: 2, RecoverThreshold: 2})
}

func seed(p *Pool, keys ...string) {
	routes := make([]Route, 0, len(keys))
	for _, k := range keys {
		routes = append(routes, Route{Key: k, Lease: k, EgressIP: "10.0.0.1"})
	}
	p.Sync(routes)
}

func TestBlockedAfterThreshold(t *testing.T) {
	p := testPool()
	seed(p, "a")

	// One failure is not enough: a free tier answers a stray 403 under load.
	p.Record("a", VerdictBlocked, time.Millisecond, "blocked")
	if got := p.Snapshots()[0].State; got != StateSuspect {
		t.Fatalf("after one failure state = %v, want suspect", got)
	}
	p.Record("a", VerdictBlocked, time.Millisecond, "blocked")
	if got := p.Snapshots()[0].State; got != StateBlocked {
		t.Fatalf("after two failures state = %v, want blocked", got)
	}
	if _, ok := p.Pick(); ok {
		t.Fatal("a blocked route must not be picked")
	}
}

// BadRequest means the request shape was wrong. It says nothing about the
// egress, so it must leave the route's health untouched.
func TestBadRequestIsNotEvidence(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictOK, time.Millisecond, "ok")
	before := p.Snapshots()[0]

	for i := 0; i < 5; i++ {
		p.Record("a", VerdictBadRequest, time.Millisecond, "shape")
	}
	after := p.Snapshots()[0]
	if after.State != before.State || after.ConsecOK != before.ConsecOK {
		t.Fatalf("bad_request changed health: before %v/%d after %v/%d",
			before.State, before.ConsecOK, after.State, after.ConsecOK)
	}
}

func TestRecoveryRequiresEvidence(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	if p.Snapshots()[0].State != StateBlocked {
		t.Fatal("precondition: route should be blocked")
	}

	p.Record("a", VerdictOK, time.Millisecond, "")
	if got := p.Snapshots()[0].State; got == StateReady {
		t.Fatal("one success must not clear a block")
	}
	p.Record("a", VerdictOK, time.Millisecond, "")
	if got := p.Snapshots()[0].State; got != StateReady {
		t.Fatalf("after two successes state = %v, want ready", got)
	}
	if _, ok := p.Pick(); !ok {
		t.Fatal("recovered route should be pickable again")
	}
}

func TestDisappearedRouteIsForgotten(t *testing.T) {
	p := testPool()
	seed(p, "a", "b")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	p.Record("a", VerdictBlocked, time.Millisecond, "")

	seed(p, "b")
	if n := len(p.Snapshots()); n != 1 {
		t.Fatalf("routes = %d, want 1", n)
	}
	// Re-adding must start from a clean slate, not a stale block.
	seed(p, "a", "b")
	for _, s := range p.Snapshots() {
		if s.Key == "a" && s.State == StateBlocked {
			t.Fatal("a re-discovered route must not inherit the old block")
		}
	}
}

func TestPickRotates(t *testing.T) {
	p := testPool()
	seed(p, "a", "b", "c")
	for _, k := range []string{"a", "b", "c"} {
		p.Record(k, VerdictOK, time.Millisecond, "")
	}

	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		r, ok := p.Pick()
		if !ok {
			t.Fatal("pick failed on a fully ready pool")
		}
		seen[r.Key]++
	}
	// Nine picks over three routes must not all land on one.
	for k, n := range seen {
		if n > 5 {
			t.Fatalf("route %s took %d/9 picks; rotation is not working", k, n)
		}
	}
}

// Only a route with positive evidence of a block is withheld. One failure is
// not enough: under passive observation nothing would ever clear it.
func TestSuspectStaysSelectable(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	if got := p.Snapshots()[0].State; got != StateSuspect {
		t.Fatalf("state = %v, want suspect", got)
	}
	if _, ok := p.Pick(); !ok {
		t.Fatal("a suspect route must remain selectable; nothing else would prove it healthy")
	}
}

// A route condemned by live traffic must be withdrawn, then come back once a
// success proves the new egress works.
func TestBlockedIsWithheldThenRecovers(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	if _, ok := p.Pick(); ok {
		t.Fatal("a blocked route must not be selected")
	}

	p.Record("a", VerdictOK, time.Millisecond, "")
	if got := p.Snapshots()[0].State; got == StateReady {
		t.Fatal("one success must not clear a block")
	}
	p.Record("a", VerdictOK, time.Millisecond, "")
	if _, ok := p.Pick(); !ok {
		t.Fatal("two successes should restore the route")
	}
}

func TestCounts(t *testing.T) {
	p := testPool()
	seed(p, "a", "b", "c")
	// Routes start ready: with no active probe there is nothing to establish
	// health, so a discovered route is usable until traffic says otherwise.
	p.Record("b", VerdictBlocked, time.Millisecond, "")
	p.Record("b", VerdictBlocked, time.Millisecond, "")

	c := p.Counts()
	if c["total"] != 3 || c["blocked"] != 1 || c["suspect"] != 0 || c["ready"] != 2 {
		t.Fatalf("counts = %+v", c)
	}
}

// A re-allocated account is a different egress under the same name. Without a
// reset, a blocked route would stay blocked forever: passive observation has no
// probe to prove recovery.
func TestResetClearsVerdict(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	if p.Snapshots()[0].State != StateBlocked {
		t.Fatal("precondition: route should be blocked")
	}

	p.Reset("a")
	s := p.Snapshots()[0]
	if s.State != StateReady || s.ConsecFail != 0 || s.LastVerdict == VerdictBlocked {
		t.Fatalf("reset left state %v fail=%d verdict=%v", s.State, s.ConsecFail, s.LastVerdict)
	}
	if _, ok := p.Pick(); !ok {
		t.Fatal("a reset route must be selectable again")
	}
}

func TestClaimEvictionGuards(t *testing.T) {
	p := testPool()
	seed(p, "a")

	// Not blocked yet: nothing to claim.
	if p.ClaimEviction("a", time.Minute) {
		t.Fatal("must not claim eviction for a healthy route")
	}

	p.Record("a", VerdictBlocked, time.Millisecond, "")
	p.Record("a", VerdictBlocked, time.Millisecond, "")
	if !p.ClaimEviction("a", time.Minute) {
		t.Fatal("should claim eviction for a blocked route")
	}
	// Second claim inside the cooldown must be refused, so concurrent blocked
	// responses collapse into one deletion.
	if p.ClaimEviction("a", time.Minute) {
		t.Fatal("second claim within cooldown must be refused")
	}

	// A failed delete releases the claim so the next attempt can retry.
	p.ReleaseEviction("a")
	if !p.ClaimEviction("a", time.Minute) {
		t.Fatal("released claim should be claimable again")
	}
}

// Only positive evidence of a blocked egress may trigger deletion. An
// unreachable route is a transient network problem, not a reason to churn.
func TestClaimEvictionRequiresBlockedVerdict(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictUnknown, time.Millisecond, "dial timeout")
	p.Record("a", VerdictUnknown, time.Millisecond, "dial timeout")
	if p.Snapshots()[0].State != StateBlocked {
		t.Fatal("precondition: repeated unknown failures should block")
	}
	if p.ClaimEviction("a", time.Minute) {
		t.Fatal("an unreachable route must not be evicted; only a blocked egress may")
	}
}
