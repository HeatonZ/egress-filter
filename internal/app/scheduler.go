// Package app wires discovery and passive eviction into one loop.
//
// There is deliberately no active prober here. Probing sends traffic that is
// not the user's: it consumes the same upstream quota the real requests need,
// and its own results are polluted by the rate limiting it causes. The evidence
// this layer acts on comes from traffic that was going to be sent anyway.
package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
	"github.com/HeatonZ/egress-filter/internal/resin"
)

// Config drives the loop.
type Config struct {
	PlatformID string
	Platform   string
	// DiscoveryInterval is how often the lease set is refreshed.
	DiscoveryInterval time.Duration
	// Evict enables deleting the lease binding of a route that live traffic
	// proved blocked.
	Evict bool
	// EvictCooldown is the minimum gap between two deletions of the same
	// account. Without it one noisy window can delete the same lease repeatedly
	// as it is re-allocated onto equally bad nodes.
	EvictCooldown time.Duration
}

// Source is one Resin instance discovery reads leases from. Several may be
// configured: each keeps its own control-plane client and platform id, and the
// routes it contributes carry its name so the data path can dial the right
// instance with the right password.
type Source struct {
	Name       string
	Client     *resin.Client
	PlatformID string
}

// Scheduler keeps the pool's route set in sync with Resin and applies
// evictions requested by the data path.
type Scheduler struct {
	Pool  *pool.Pool
	Resin *resin.Client
	// Sources are the Resin instances to read leases from. When empty the
	// single Resin client plus Cfg.PlatformID is used, so existing deployments
	// keep working unchanged.
	Sources []Source
	Cfg     Config
	Log     *slog.Logger

	// evictCh carries accounts the reverse entry has condemned. It is buffered
	// and written without blocking: the request path must never wait on the
	// control plane.
	evictCh chan string

	mu      sync.Mutex
	evicted int64
	failed  int64
	// owners maps a route key to the instance that produced it, so eviction
	// deletes from the right control plane.
	owners map[string]Source
}

// New builds a scheduler.
func New(p *pool.Pool, rc *resin.Client, cfg Config, log *slog.Logger) *Scheduler {
	return &Scheduler{
		Pool:    p,
		Resin:   rc,
		Cfg:     cfg,
		Log:     log,
		evictCh: make(chan string, 64),
	}
}

// Evict queues an account for deletion. Safe to call from the request path.
func (s *Scheduler) Evict(account string) {
	select {
	case s.evictCh <- account:
	default:
		// Queue full: dropping is better than blocking a user's request, but the
		// route must not stay withdrawn because of it. A blocked route is never
		// selected, so nothing else would ever queue it again — clearing the
		// streak lets the next real request use it and count afresh.
		s.Log.Warn("evict queue full, dropping request", "account", account)
		s.releaseWithdrawal(account)
	}
}

// Run blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	// Discover immediately, otherwise the first seconds after start have no
	// routes and every caller gets a 503.
	s.discover(ctx)

	discTick := time.NewTicker(s.Cfg.DiscoveryInterval)
	defer discTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-discTick.C:
			s.discover(ctx)
		case account := <-s.evictCh:
			s.evict(ctx, account)
		}
	}
}

// sources returns the configured instances, defaulting to the single client.
func (s *Scheduler) sources() []Source {
	if len(s.Sources) > 0 {
		return s.Sources
	}
	if s.Resin == nil {
		return nil
	}
	return []Source{{Name: "default", Client: s.Resin, PlatformID: s.Cfg.PlatformID}}
}

// discover refreshes the route set from every configured Resin instance.
func (s *Scheduler) discover(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sources := s.sources()
	// With one instance the key stays the bare account, so existing status
	// output and eviction cooldowns are unchanged. With several, the name has to
	// be part of the key or two instances holding the same account name would
	// collapse into one route.
	multi := len(sources) > 1

	routes := make([]pool.Route, 0, 64)
	owners := make(map[string]Source, 64)
	for _, src := range sources {
		leases, err := src.Client.Leases(cctx, src.PlatformID)
		if err != nil {
			s.Log.Warn("lease discovery failed", "upstream", src.Name, "error", err)
			continue
		}
		for _, l := range leases {
			if l.Account == "" {
				continue
			}
			key := l.Account
			if multi {
				key = src.Name + "/" + l.Account
			}
			routes = append(routes, pool.Route{
				Key:      key,
				Lease:    l.Account,
				EgressIP: l.EgressIP,
				Upstream: src.Name,
			})
			owners[key] = src
		}
	}

	s.mu.Lock()
	s.owners = owners
	s.mu.Unlock()

	before := s.Pool.Snapshots()
	s.Pool.Sync(routes)

	// A lease whose node changed is a different egress under the same name.
	// Carrying the old verdict over would keep a re-allocated account marked
	// blocked forever, since with no active probe nothing would ever clear it.
	egress := make(map[string]string, len(routes))
	for _, r := range routes {
		egress[r.Key] = r.EgressIP
	}
	for _, prev := range before {
		now, ok := egress[prev.Key]
		if ok && now != "" && prev.EgressIP != "" && now != prev.EgressIP {
			s.Pool.Reset(prev.Key)
			s.Log.Info("lease re-allocated, health reset", "account", prev.Key,
				"old_egress", prev.EgressIP, "new_egress", now)
		}
	}

	s.Log.Info("leases discovered", "count", len(routes), "counts", s.Pool.Counts())
}

// evict deletes one account's lease binding if the pool still condemns it.
func (s *Scheduler) evict(ctx context.Context, account string) {
	if !s.Cfg.Evict {
		// Eviction is off, so this route will never get a new lease. Leaving it
		// withdrawn would retire it permanently: a blocked route is never
		// selected, so nothing in the passive path could ever clear it.
		s.releaseWithdrawal(account)
		return
	}
	cooldown := s.Cfg.EvictCooldown
	if cooldown <= 0 {
		cooldown = 10 * time.Minute
	}
	src, lease, ok := s.ownerOf(account)
	if !ok {
		s.Pool.ReleaseEviction(account)
		s.Log.Warn("evict: route has no owning upstream", "route", account)
		// Nothing was deleted, so the failures still stand against a route that
		// will keep being used. Releasing it lets the count start over instead
		// of retiring the route for good.
		s.releaseWithdrawal(account)
		return
	}

	// Claim before deleting so concurrent blocked responses for the same
	// account collapse into one deletion.
	if !s.Pool.ClaimEviction(account, cooldown) {
		// Either the lease was already re-allocated inside the cooldown window
		// or the route recovered while this was queued. Either way it must not
		// stay withdrawn: nothing in the passive path can clear a route that is
		// never selected.
		s.releaseWithdrawal(account)
		return
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := src.Client.DeleteLease(cctx, src.PlatformID, lease); err != nil {
		s.Pool.ReleaseEviction(account)
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		s.Log.Warn("delete lease failed", "account", lease, "upstream", src.Name, "error", err)
		// The lease still points at the bad node, but leaving the route blocked
		// would retire it for good: blocked routes are never selected, so no
		// further failure would ever queue another delete attempt. Release the
		// withdrawal and let the next threshold retry the deletion.
		s.releaseWithdrawal(account)
		return
	}

	// The lease is gone, so the next request through this account gets a fresh
	// node. Clearing the streak in the same step is the whole point of the
	// design: the failures belonged to the old egress, and carrying them over
	// would withdraw the route again on its first unlucky response.
	s.Pool.Reset(account)

	s.mu.Lock()
	s.evicted++
	s.mu.Unlock()
	s.Log.Info("evicted blocked lease", "account", lease, "upstream", src.Name)
}

// releaseWithdrawal clears the failure streak of a withdrawn route so the next
// real request can use it and count afresh.
//
// This is the other half of "count to the threshold, then delete the lease": the
// counter belongs to the lease that produced the failures. Once that lease is
// gone — deleted, or kept because nothing could delete it — carrying the old
// count forward would withdraw the route again on its very next unlucky
// response, and since a withdrawn route is never selected nothing in the passive
// path could ever clear it.
func (s *Scheduler) releaseWithdrawal(key string) {
	if !s.Pool.Blocked(key) {
		return
	}
	s.Pool.Reset(key)
	s.Log.Info("failure count cleared", "account", key)
}

// sweepWithdrawals is gone on purpose: with passive-only observation a blocked
// route is never selected, so it can never record the success that would clear
// it. Every withdrawal is therefore released where it is handled — after the
// lease is deleted, after a failed delete, and when the cooldown refuses a
// second deletion — and no timer is needed.

// ownerOf resolves a route key to the instance that owns it and the bare lease
// name that instance knows.
//
// Discovery is not the authority here: a route can exist because a client named
// a lease Resin has not been asked for before. The route itself records its
// instance, so eviction follows that and only falls back to the discovered
// owner map when the route does not say.
func (s *Scheduler) ownerOf(key string) (Source, string, bool) {
	s.mu.Lock()
	owner, known := s.owners[key]
	s.mu.Unlock()

	var sn pool.Snapshot
	found := false
	for _, cand := range s.Pool.Snapshots() {
		if cand.Key == key {
			sn, found = cand, true
			break
		}
	}
	if !found {
		return Source{}, "", false
	}

	if known {
		return owner, sn.Lease, true
	}
	for _, src := range s.sources() {
		if src.Name == sn.Upstream {
			return src, sn.Lease, true
		}
	}
	if single := s.sources(); len(single) == 1 {
		return single[0], sn.Lease, true
	}
	return Source{}, "", false
}

// Evicted returns how many lease bindings were dropped.
func (s *Scheduler) Evicted() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

// EvictFailed returns how many deletion attempts errored.
func (s *Scheduler) EvictFailed() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}
