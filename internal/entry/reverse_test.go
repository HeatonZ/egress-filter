package entry

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func seeded() *pool.Pool {
	p := pool.New(pool.Options{FailThreshold: 2, RecoverThreshold: 2})
	p.Sync([]pool.Route{
		{Key: "leaseA", Lease: "leaseA", EgressIP: "1.1.1.1"},
		{Key: "leaseB", Lease: "leaseB", EgressIP: "2.2.2.2"},
	})
	for _, k := range []string{"leaseA", "leaseB"} {
		p.Record(k, pool.VerdictOK, time.Millisecond, "")
	}
	return p
}

// The caller's URL shape must survive unchanged apart from the account. This is
// what makes migration a host swap instead of a config rewrite.
func TestReverseRewritesAccountAndPath(t *testing.T) {
	var gotPath string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: ok\n\n")
	}))
	defer fake.Close()

	r := NewReverse(seeded(), fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/11123zzzsf/opencode.auto/https/opencode.ai/inference/v1/chat/completions",
		"application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	wantPrefix := "/11123zzzsf/opencode.lease"
	if !strings.HasPrefix(gotPath, wantPrefix) {
		t.Fatalf("upstream path = %q, want prefix %q", gotPath, wantPrefix)
	}
	if !strings.HasSuffix(gotPath, "/https/opencode.ai/inference/v1/chat/completions") {
		t.Fatalf("upstream path lost the route suffix: %q", gotPath)
	}
	if resp.Header.Get("X-Egress-Route") == "" {
		t.Fatal("response must report which route served it")
	}
}

// A healthy requested account is honoured, because one account is one egress
// and switching egress pads the upstream's prompt cache.
func TestReverseHonoursHealthyAccount(t *testing.T) {
	var gotPath string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(200)
	}))
	defer fake.Close()

	r := NewReverse(seeded(), fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tok/opencode.leaseB/https/opencode.ai/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !strings.HasPrefix(gotPath, "/tok/opencode.leaseB/") {
		t.Fatalf("healthy account was not honoured: %q", gotPath)
	}
}

// When the requested account is blocked the caller must still get served,
// through a different egress.
func TestReverseFailsOverFromBlockedAccount(t *testing.T) {
	var gotPath string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(200)
	}))
	defer fake.Close()

	p := seeded()
	for i := 0; i < 2; i++ {
		p.Record("leaseA", pool.VerdictBlocked, time.Millisecond, "")
	}

	r := NewReverse(p, fake.URL, "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tok/opencode.leaseA/https/opencode.ai/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if strings.Contains(gotPath, "leaseA") {
		t.Fatalf("blocked account was still used: %q", gotPath)
	}
	if !strings.Contains(gotPath, "leaseB") {
		t.Fatalf("expected failover to leaseB, got %q", gotPath)
	}
}

func TestReverseReportsExhaustedPool(t *testing.T) {
	p := seeded()
	for _, k := range []string{"leaseA", "leaseB"} {
		for i := 0; i < 2; i++ {
			p.Record(k, pool.VerdictBlocked, time.Millisecond, "")
		}
	}
	r := NewReverse(p, "http://127.0.0.1:1", "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tok/opencode.auto/https/opencode.ai/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestReverseRejectsForeignPlatform(t *testing.T) {
	r := NewReverse(seeded(), "http://127.0.0.1:1", "opencode", quietLogger())
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tok/other.leaseA/https/opencode.ai/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
