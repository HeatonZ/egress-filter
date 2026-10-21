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

// Scheduler keeps the pool's route set in sync with Resin and applies
// evictions requested by the data path.
type Scheduler struct {
	Pool  *pool.Pool
	Resin *resin.Client
	Cfg   Config
	Log   *slog.Logger

	// evictCh carries accounts the reverse entry has condemned. It is buffered
	// and written without blocking: the request path must never wait on the
	// control plane.
	evictCh chan string

	mu      sync.Mutex
	evicted int64
	failed  int64
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
		// Queue full: dropping is better than blocking a user's request. The
		// next blocked response for this account will queue it again.
		s.Log.Warn("evict queue full, dropping request", "account", account)
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

// discover refreshes the route set from Resin.
func (s *Scheduler) discover(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	leases, err := s.Resin.Leases(cctx, s.Cfg.PlatformID)
	if err != nil {
		s.Log.Warn("lease discovery failed", "error", err)
		return
	}
	routes := make([]pool.Route, 0, len(leases))
	for _, l := range leases {
		if l.Account == "" {
			continue
		}
		routes = append(routes, pool.Route{
			Key:      l.Account,
			Lease:    l.Account,
			EgressIP: l.EgressIP,
		})
	}
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
		return
	}
	cooldown := s.Cfg.EvictCooldown
	if cooldown <= 0 {
		cooldown = 10 * time.Minute
	}
	// Claim before deleting so concurrent blocked responses for the same
	// account collapse into one deletion.
	if !s.Pool.ClaimEviction(account, cooldown) {
		return
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := s.Resin.DeleteLease(cctx, s.Cfg.PlatformID, account); err != nil {
		s.Pool.ReleaseEviction(account)
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		s.Log.Warn("delete lease failed", "account", account, "error", err)
		return
	}

	s.mu.Lock()
	s.evicted++
	s.mu.Unlock()
	s.Log.Info("evicted blocked lease", "account", account)
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
