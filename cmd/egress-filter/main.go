// Command egress-filter selects a working egress before the request is sent.
//
// It sits between the API frontends and Resin and offers the same two proxy
// shapes the frontends already use:
//
//	reverse:  /{token}/{platform}.{account}/{proto}/{host}/...   (account may be "auto")
//	forward:  SOCKS5 + HTTP CONNECT on one port; the username is the preferred account
//
// A background prober replays the real upstream request through each lease and
// evicts the ones whose egress the upstream refuses, so a bad route is removed
// before traffic lands on it rather than after it fails.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/HeatonZ/egress-filter/internal/app"
	"github.com/HeatonZ/egress-filter/internal/entry"
	"github.com/HeatonZ/egress-filter/internal/mitm"
	"github.com/HeatonZ/egress-filter/internal/pool"
	"github.com/HeatonZ/egress-filter/internal/resin"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(env("EF_LOG_LEVEL", "info")),
	}))

	cfg := loadConfig()
	if cfg.Password == "" {
		log.Error("EF_PROXY_PASSWORD is required: the aggregator must authenticate its clients")
		os.Exit(1)
	}

	p := pool.New(pool.Options{
		FailThreshold:    cfg.FailThreshold,
		RecoverThreshold: cfg.RecoverThreshold,
		LazyTTL:          cfg.LazyTTL,
	})
	// One registry is shared by every entry: a route carries the name of the
	// Resin instance that owns its lease, and the entry dials that instance with
	// that instance's own token.
	registry := make(entry.Upstreams, len(cfg.Upstreams))
	sources := make([]app.Source, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		if u.PlatformID == "" {
			log.Error("upstream has no platform id", "upstream", u.Name)
			os.Exit(1)
		}
		registry[u.Name] = entry.Upstream{
			Name:      u.Name,
			ProxyAddr: u.ProxyAddr,
			Token:     u.ProxyToken,
			BaseURL:   u.ResinURL,
		}
		sources = append(sources, app.Source{
			Name:       u.Name,
			Client:     resin.New(u.ResinURL, u.AdminToken),
			PlatformID: u.PlatformID,
		})
		log.Info("upstream configured", "name", u.Name, "resin", u.ResinURL,
			"proxy", u.ProxyAddr, "platform_id", u.PlatformID)
	}

	rev := entry.NewReverse(p, cfg.ResinURL, cfg.Platform, log)
	rev.Upstreams = registry
	if cfg.HeaderTimeout > 0 {
		rev.Transport.ResponseHeaderTimeout = cfg.HeaderTimeout
	}

	fwd := &entry.Forward{
		Pool:        p,
		Log:         log,
		Upstream:    cfg.ProxyAddr,
		Token:       cfg.ProxyToken,
		Password:    cfg.Password,
		Upstreams:   registry,
		Platform:    cfg.Platform,
		DialTimeout: 15 * time.Second,
	}

	sched := app.New(p, sources[0].Client, app.Config{
		PlatformID:        cfg.PlatformID,
		Platform:          cfg.Platform,
		DiscoveryInterval: cfg.DiscoveryInterval,
		Evict:             cfg.Evict,
		EvictCooldown:     cfg.EvictCooldown,
	}, log)
	sched.Sources = sources
	rev.Evictor = sched

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Evict {
		log.Info("eviction enabled: blocked leases will be deleted and re-allocated")
	}

	started := time.Now()

	// Status server is separate from the data path on purpose: a status request
	// must never compete with streaming responses for connections.
	statusMux := http.NewServeMux()
	statusMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		c := p.Counts()
		if c["ready"] == 0 && c["total"] > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "no ready egress (total=%d)\n", c["total"])
			return
		}
		fmt.Fprintf(w, "ok ready=%d total=%d\n", c["ready"], c["total"])
	})
	statusMux.HandleFunc("/status", app.Status(p, started, sched.Evicted))

	statusSrv := &http.Server{Addr: cfg.StatusAddr, Handler: statusMux}
	revSrv := &http.Server{
		Addr:    cfg.ReverseAddr,
		Handler: rev,
		// No read/write timeout: SSE responses are long-lived by design. A
		// blanket WriteTimeout would cut every stream at the deadline.
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		log.Info("status listening", "addr", cfg.StatusAddr)
		if err := statusSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("status server", "error", err)
		}
	}()
	go func() {
		log.Info("reverse listening", "addr", cfg.ReverseAddr, "upstream", cfg.ResinURL)
		if err := revSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("reverse server", "error", err)
		}
	}()

	fwdLn, err := net.Listen("tcp", cfg.ForwardAddr)
	if err != nil {
		log.Error("forward listen", "addr", cfg.ForwardAddr, "error", err)
		os.Exit(1)
	}
	go func() {
		log.Info("forward listening", "addr", cfg.ForwardAddr, "upstream", cfg.ProxyAddr)
		if err := fwd.Serve(fwdLn); err != nil {
			log.Error("forward server", "error", err)
		}
	}()

	// The terminating proxy is optional: it requires every client to trust its
	// CA, which is a deployment decision rather than a default.
	var termLn net.Listener
	if cfg.TerminateAddr != "" {
		if ca, err := mitm.LoadOrCreate(cfg.CAFile); err != nil {
			// The terminating entry is optional and the other two are not. A
			// bad CA directory (wrong owner, read-only volume) must not take the
			// reverse and SOCKS5 entries down with it.
			log.Error("load ca, terminating entry disabled",
				"dir", cfg.CAFile, "error", err,
				"hint", "the container user must own this directory")
		} else if ln, err := net.Listen("tcp", cfg.TerminateAddr); err != nil {
			// Same reasoning: a busy port must not stop the other entries.
			log.Error("terminate listen, entry disabled",
				"addr", cfg.TerminateAddr, "error", err)
		} else {
			termLn = ln
			term := &entry.Terminator{
				Pool:          p,
				Log:           log,
				CA:            ca,
				Upstream:      cfg.ProxyAddr,
				Token:         cfg.Password,
				Upstreams:     registry,
				Platform:      cfg.Platform,
				DialTimeout:   15 * time.Second,
				HeaderTimeout: cfg.HeaderTimeout,
				Evictor:       sched,
			}
			termSrv := &http.Server{Handler: term, ReadHeaderTimeout: 30 * time.Second}
			go func() {
				log.Info("terminating forward proxy listening", "addr", cfg.TerminateAddr,
					"ca_cert", cfg.CAFile+"/ca.crt")
				if err := termSrv.Serve(termLn); err != nil && err != http.ErrServerClosed {
					log.Error("terminate server", "error", err)
				}
			}()
		}
	}

	go sched.Run(ctx)

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	revSrv.Shutdown(shutdownCtx)
	statusSrv.Shutdown(shutdownCtx)
	fwdLn.Close()
}

type config struct {
	ReverseAddr string
	ForwardAddr string
	StatusAddr  string

	// TerminateAddr serves a TLS-terminating forward proxy, which is the only
	// forward shape that can see HTTP status codes.
	TerminateAddr string
	CAFile        string

	ResinURL   string
	ResinToken string
	Platform   string
	PlatformID string

	ProxyAddr  string
	ProxyToken string
	TargetHost string

	// Password is the aggregator's own password: the secret clients present to
	// this entry. Each Resin instance keeps its own token in Upstreams, so the
	// two can be rotated independently.
	Password string
	// Upstreams are the Resin instances this entry aggregates.
	Upstreams []upstreamConfig

	ProbeInterval     time.Duration
	DiscoveryInterval time.Duration
	ProbeConcurrency  int
	FailThreshold     int
	RecoverThreshold  int
	Evict             bool
	EvictCooldown     time.Duration
	// LazyTTL expires a route a client named that discovery never lists.
	LazyTTL time.Duration
	// HeaderTimeout bounds how long one egress may take to answer with
	// response headers before the attempt counts as a timeout.
	HeaderTimeout time.Duration
}

// upstreamConfig describes one Resin instance. It is the JSON shape accepted by
// EF_UPSTREAMS.
type upstreamConfig struct {
	Name       string `json:"name"`
	ResinURL   string `json:"resin_url"`
	AdminToken string `json:"admin_token"`
	ProxyAddr  string `json:"proxy_addr"`
	ProxyToken string `json:"proxy_token"`
	PlatformID string `json:"platform_id"`
}

func loadConfig() config {
	c := config{
		ReverseAddr:       env("EF_LISTEN_REVERSE", ":8080"),
		ForwardAddr:       env("EF_LISTEN_FORWARD", ":1080"),
		StatusAddr:        env("EF_LISTEN_STATUS", ":9090"),
		TerminateAddr:     env("EF_LISTEN_TERMINATE", ""),
		CAFile:            env("EF_CA_DIR", "/data/ca"),
		ResinURL:          env("EF_RESIN_URL", "http://resin:2260"),
		ResinToken:        env("EF_RESIN_TOKEN", ""),
		Platform:          env("EF_PLATFORM", "opencode"),
		PlatformID:        env("EF_PLATFORM_ID", ""),
		ProxyAddr:         env("EF_PROXY_ADDR", "resin:2260"),
		ProxyToken:        env("EF_PROXY_TOKEN", ""),
		TargetHost:        env("EF_TARGET_HOST", "opencode.ai"),
		ProbeInterval:     duration("EF_PROBE_INTERVAL", 10*time.Minute),
		DiscoveryInterval: duration("EF_DISCOVERY_INTERVAL", 60*time.Second),
		ProbeConcurrency:  integer("EF_PROBE_CONCURRENCY", 4),
		FailThreshold:     integer("EF_FAIL_THRESHOLD", 5),
		RecoverThreshold:  integer("EF_RECOVER_THRESHOLD", 2),
		Evict:             boolean("EF_EVICT", false),
		EvictCooldown:     duration("EF_EVICT_COOLDOWN", 10*time.Minute),
		LazyTTL:           duration("EF_LAZY_TTL", 10*time.Minute),
		HeaderTimeout:     duration("EF_UPSTREAM_HEADER_TIMEOUT", 60*time.Second),
	}
	// The aggregator password defaults to the old single-instance token so an
	// existing deployment keeps working without a new variable.
	c.Password = env("EF_PROXY_PASSWORD", c.ProxyToken)
	c.Upstreams = loadUpstreams(c)
	return c
}

// loadUpstreams reads EF_UPSTREAMS (a JSON array) and falls back to the single
// instance described by the older EF_* variables.
func loadUpstreams(c config) []upstreamConfig {
	raw := env("EF_UPSTREAMS", "")
	if raw == "" {
		return []upstreamConfig{{
			Name:       "default",
			ResinURL:   c.ResinURL,
			AdminToken: c.ResinToken,
			ProxyAddr:  c.ProxyAddr,
			ProxyToken: c.ProxyToken,
			PlatformID: c.PlatformID,
		}}
	}
	var out []upstreamConfig
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		slog.Error("EF_UPSTREAMS is not valid JSON", "error", err)
		os.Exit(1)
	}
	for i := range out {
		u := &out[i]
		if u.Name == "" {
			u.Name = "default"
		}
		if u.ResinURL == "" {
			u.ResinURL = c.ResinURL
		}
		if u.ProxyAddr == "" {
			u.ProxyAddr = c.ProxyAddr
		}
		if u.ProxyToken == "" {
			u.ProxyToken = c.ProxyToken
		}
		if u.PlatformID == "" {
			u.PlatformID = c.PlatformID
		}
	}
	if len(out) == 0 {
		slog.Error("EF_UPSTREAMS is empty")
		os.Exit(1)
	}
	return out
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func integer(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func boolean(k string, def bool) bool {
	if v, ok := os.LookupEnv(k); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

func duration(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			return d
		}
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
