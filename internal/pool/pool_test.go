package pool

import (
	"io"
	"os"
	"testing"
	"time"
)

// testPool uses the production defaults so the tests exercise the behaviour
// that actually ships rather than a hand-picked threshold.
func testPool() *Pool {
	return New(Options{})
}

// defaultThreshold is the shipped default; tests assert against it instead of a
// literal so changing the default cannot silently invalidate them.
const defaultThreshold = 5

// failN records n blocked verdicts on key.
func failN(p *Pool, key string, n int) {
	for i := 0; i < n; i++ {
		p.Record(key, VerdictBlocked, time.Millisecond, "blocked")
	}
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

	// Four failures are not enough: the threshold is five consecutive.
	for i := 1; i <= 4; i++ {
		p.Record("a", VerdictBlocked, time.Millisecond, "blocked")
		if got := p.Snapshots()[0].State; got != StateSuspect {
			t.Fatalf("after %d failures state = %v, want suspect", i, got)
		}
	}
	p.Record("a", VerdictBlocked, time.Millisecond, "blocked")
	if got := p.Snapshots()[0].State; got != StateBlocked {
		t.Fatalf("after five failures state = %v, want blocked", got)
	}
	if _, ok := p.Pick(); ok {
		t.Fatal("a blocked route must not be picked")
	}
}

// A single success must reset the streak: a route that still serves traffic is
// not blocked, however many failures preceded it.
func TestSuccessResetsFailureStreak(t *testing.T) {
	p := testPool()
	seed(p, "a")

	for i := 0; i < 4; i++ {
		p.Record("a", VerdictBlocked, time.Millisecond, "blocked")
	}
	p.Record("a", VerdictOK, time.Millisecond, "ok")
	if got := p.Snapshots()[0].ConsecFail; got != 0 {
		t.Fatalf("consecutive failures after a success = %d, want 0", got)
	}

	// Four more failures still must not withdraw it, because the streak
	// restarted.
	for i := 0; i < 4; i++ {
		p.Record("a", VerdictBlocked, time.Millisecond, "blocked")
	}
	if got := p.Snapshots()[0].State; got == StateBlocked {
		t.Fatal("route withdrawn after a success restarted the streak")
	}
}

// Every verdict except OK is a failure, so a 400 withdraws the route too.
func TestBadRequestCountsTowardWithdrawal(t *testing.T) {
	p := testPool()
	seed(p, "a")
	p.Record("a", VerdictOK, time.Millisecond, "ok")

	for i := 0; i < defaultThreshold; i++ {
		p.Record("a", VerdictBadRequest, time.Millisecond, "upstream 400")
	}
	after := p.Snapshots()[0]
	if after.State != StateBlocked {
		t.Fatalf("state after the threshold = %v, want blocked", after.State)
	}
	if after.ConsecOK != 0 {
		t.Fatalf("a failure left the success streak at %d, want 0", after.ConsecOK)
	}
}

func TestRecoveryRequiresEvidence(t *testing.T) {
	p := testPool()
	seed(p, "a")
	failN(p, "a", defaultThreshold)
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
	failN(p, "a", defaultThreshold)

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
	failN(p, "a", defaultThreshold)
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
	failN(p, "b", defaultThreshold)

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
	failN(p, "a", defaultThreshold)
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

	failN(p, "a", defaultThreshold)
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
	for i := 0; i < defaultThreshold; i++ {
		p.Record("a", VerdictUnknown, time.Millisecond, "dial timeout")
	}
	if p.Snapshots()[0].State != StateBlocked {
		t.Fatal("precondition: repeated unknown failures should block")
	}
	if p.ClaimEviction("a", time.Minute) {
		t.Fatal("an unreachable route must not be evicted; only a blocked egress may")
	}
}

// A timeout is a failure like any other and withdraws the route after the
// threshold, exactly as a blocked verdict does.
func TestTimeoutCountsTowardWithdrawal(t *testing.T) {
	p := testPool()
	seed(p, "a", "b")

	for i := 0; i < defaultThreshold; i++ {
		p.Record("a", VerdictTimeout, time.Second, "read response: i/o timeout")
	}
	snap := p.Snapshots()
	if snap[0].State != StateBlocked || snap[0].LastVerdict != VerdictTimeout {
		t.Fatalf("want a blocked on timeout, got %v (%v)", snap[0].State, snap[0].LastVerdict)
	}
	if snap[1].State != StateReady {
		t.Fatalf("the untouched route was demoted: %v", snap[1].State)
	}
}

// A 5xx withdraws the route the same way, and one success clears the streak.
func TestServerErrorCountsAndSuccessResetsIt(t *testing.T) {
	p := testPool()
	seed(p, "a")

	for i := 0; i < defaultThreshold-1; i++ {
		p.Record("a", VerdictServerError, time.Second, "upstream 5xx")
	}
	p.Record("a", VerdictOK, time.Millisecond, "served live traffic")
	if got := p.Snapshots()[0].State; got != StateReady {
		t.Fatalf("state after a success = %v, want ready", got)
	}
	for i := 0; i < defaultThreshold; i++ {
		p.Record("a", VerdictServerError, time.Second, "upstream 5xx")
	}
	if got := p.Snapshots()[0].State; got != StateBlocked {
		t.Fatalf("state after the threshold = %v, want blocked", got)
	}
}

func TestIsTimeoutRecognisesDeadlines(t *testing.T) {
	if IsTimeout(io.EOF) {
		t.Fatal("EOF is a refusal, not a deadline")
	}
	if !IsTimeout(os.ErrDeadlineExceeded) {
		t.Fatal("os.ErrDeadlineExceeded must count as a timeout")
	}
}
