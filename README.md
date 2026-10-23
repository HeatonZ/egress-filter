# egress-filter

Sits between API frontends and a Resin proxy pool, and hands out only the
egresses that are actually working. Two entry shapes, one health pool.

```
client ──► egress-filter ──► resin ──► upstream
           (picks egress)     (lease = one egress)
```

## Why

Resin binds an account name to a sticky lease, and a lease is one egress IP.
Some egresses are refused by the upstream. Picking at request time costs one
routing decision; discovering the problem afterwards costs a failed request and
a re-allocated lease.

## Two entries

**Reverse proxy** — the path shape is identical to Resin's, so migrating a
caller is a host swap:

```
http://egress-filter:8080/{token}/{platform}.{account}/{proto}/{host}/...
```

`account` may be `auto` (pool picks), a specific name (preferred, honoured while
not blocked), or `X-Egress-Pin: <account>`.

**Forward proxy** — SOCKS5 and HTTP CONNECT on one port. There is no URL path to
carry an account, so it travels in the proxy credentials: the SOCKS5 username
(or `Proxy-Authorization` user) is the preferred account.

```
socks5h://opencode.freeproxy30:<EF_PROXY_PASSWORD>@egress-filter:1080
http://opencode.auto:<EF_PROXY_PASSWORD>@egress-filter:1080
```

The password is this entry's own (`EF_PROXY_PASSWORD`), not a Resin token, and it
is mandatory: a SOCKS5 client that offers only no-auth is refused rather than
quietly let through.

## The caller decides the lease

A lease name in the request is passed through to Resin unchanged. Resin creates a
lease on first use, so a name a caller just configured works immediately — this
layer does not require a discovery pass to have listed it first. Discovery only
reports what already exists, to learn egress IPs and to find leases worth
evicting.

Consequences worth knowing:

- A route a caller names stays in the pool across discovery refreshes, keeping
  its failure streak, until discovery adopts it. If discovery never lists it, it
  expires after `EF_LAZY_TTL` idle so a mistyped name cannot sit in `/status`
  forever. Once adopted it behaves like any discovered route and disappears when
  the lease does.
- A lease that live traffic has already proved blocked is refused rather than
  forwarded. That is positive evidence, not absence of evidence, so it outranks
  the caller's wish.
- The reverse entry falls back to another route when the named lease is blocked;
  the forward entries fail instead, because a client that pinned a name has its
  own lease table and silent rerouting would break its session affinity.

## Passive only

There is no active prober. Probing would consume the same upstream quota the
real requests need, and its results are polluted by the rate limiting it causes.
Evidence comes from traffic that was going to be sent anyway.

Each response is classified into two outcomes, not three:

- **2xx** — the egress works; clears the failure streak
- **anything else** — 403, 400, 429, 5xx, a transport error, a timeout — the
  route did not serve this request, so it counts toward withdrawal

The status code and body stay in `lastDetail` so operators can tell a blocked
egress from a rate-limited one.

**429 is acted on separately.** A rate-limited egress is out of quota right
now, so it is withdrawn on `EF_RATE_LIMIT_THRESHOLD` consecutive 429s
(default `1`) instead of the shared `EF_FAIL_THRESHOLD`. Waiting for five kept
real requests going to a node that could not serve them. Everything else — a
5xx, a timeout, a 403 that is not the request shape — still needs the full
streak. Set it higher to make 429s share the ordinary streak.

**A blocked 403 is acted on separately too.** When the body names this egress
(abusive traffic, free tier not available from your network), the egress is
proven dead for this upstream, so it is withdrawn on `EF_BLOCKED_THRESHOLD`
consecutive responses (default `1`). A 403 that blames the request shape is a
configuration problem: it counts toward the ordinary streak but does not
rotate the lease, because draining the pool would not fix it.

The failure count advances in every case, so `/status` and the logs read the
same as for any other failure.

Be aware of the trade-off: if the *whole pool* is answering 429, one-response
rotation churns every lease and fixes nothing, because the shortage is upstream
quota rather than a bad egress. Watch `evicted_total` against `counts` after
turning this down.

## The forward entry cannot see status codes

A SOCKS5 CONNECT only carries bytes. The client speaks TLS end to end, so the
proxy never learns whether the upstream answered 200 or 403 — which is the one
signal this service exists to act on. Counting only connection-level failures
misses every "connected fine, then got blocked" case, and that is the common
one.

`EF_LISTEN_TERMINATE` turns on a second forward entry that terminates TLS: it
presents a certificate for the upstream host signed by its own CA, reads the
request in the clear, then opens its own TLS connection upstream (verifying the
real certificate, never downgrading). Status codes and error bodies become
visible, and the same three-way classification as the reverse entry applies.

The cost is trust. Every client using this port must trust `EF_CA_DIR/ca.crt`.
The CA is generated once and persisted; regenerating it breaks every client, so
the directory must be a volume.

Pin an egress per request with `X-Egress-Route: <account>`; without it the pool
picks one.

## Withdrawal

After `EF_FAIL_THRESHOLD` consecutive failures the route is withheld, and its
lease binding is deleted so Resin re-allocates it. Deletion is rate-limited per
account (`EF_EVICT_COOLDOWN`) so one noisy window cannot churn the same lease
repeatedly.

**A withdrawal is always a pause, never a retirement.** Every entry that
withdraws a route asks for eviction (reverse, TLS-terminating, and SOCKS5 — the
last one on a failed dial, which is all a byte tunnel can observe). When the
lease is deleted the streak is cleared in the same step: the failures belonged
to the old egress, and carrying them onto the new one would withdraw it again on
its first unlucky response. When no deletion happens — eviction disabled, no
owning upstream, a failed delete, a second withdrawal inside the cooldown, a
full queue — the streak is cleared in place instead, because a withheld route is
never selected and so could never record the success that clears it.

`EF_BLOCKED_TTL` is the backstop behind all of that: any withdrawal still in
place after it is reopened, whoever failed to release it. A route must never be
stuck, whatever any caller did or failed to do.

Eviction is **off by default**. Run a while with `EF_EVICT=false` and read
`/status` before enabling it.

## Configuration

| variable | default | meaning |
| --- | --- | --- |
| `EF_PROXY_PASSWORD` | *(falls back to `EF_PROXY_TOKEN`)* | **This entry's own password.** Clients authenticate with it; it is independent of every Resin token |
| `EF_UPSTREAMS` | *(empty)* | JSON array of Resin instances, see below; empty means one instance from the `EF_RESIN_*`/`EF_PROXY_*` vars |
| `EF_RESIN_URL` | `http://resin:2260` | default instance's control plane and proxy |
| `EF_RESIN_TOKEN` | — | admin token, required |
| `EF_PLATFORM_ID` | — | platform UUID, required |
| `EF_PLATFORM` | `opencode` | platform name used in the path and SOCKS username |
| `EF_PROXY_TOKEN` | — | default instance's Resin token, used for the hop to Resin |
| `EF_LISTEN_REVERSE` | `:8080` | reverse entry |
| `EF_LISTEN_FORWARD` | `:1080` | forward entry |
| `EF_LISTEN_STATUS` | `:9090` | `/healthz`, `/status` |
| `EF_LISTEN_TERMINATE` | *(off)* | TLS-terminating forward entry; empty disables it |
| `EF_CA_DIR` | `/data/ca` | where the signing CA is stored; must persist |
| `EF_DISCOVERY_INTERVAL` | `60s` | lease refresh |
| `EF_FAIL_THRESHOLD` | `5` | consecutive ordinary failures before withdrawal |
| `EF_BLOCKED_THRESHOLD` | `1` | consecutive blocked 403s before withdrawal; a blocked egress is dead, not unlucky |
| `EF_RATE_LIMIT_THRESHOLD` | `1` | consecutive 429s before withdrawal; separate because a 429 is a quota state, not bad luck |
| `EF_EVICT` | `false` | delete leases of blocked routes |
| `EF_EVICT_COOLDOWN` | `10m` | minimum gap between deletions of one account |
| `EF_LAZY_TTL` | `10m` | how long a client-named lease discovery never lists stays in the pool |
| `EF_BLOCKED_TTL` | `2m` | how long a withdrawal holds before the route is reopened regardless |

## Several Resin instances

Set `EF_UPSTREAMS` to aggregate more than one Resin behind this entry. Each
instance keeps its own token, and the routes it contributes carry its name, so
the data path dials the right control plane without sharing credentials:

```json
[
  {"name":"main","resin_url":"http://resin:2260","admin_token":"...",
   "proxy_addr":"resin:2260","proxy_token":"...","platform_id":"<uuid>"},
  {"name":"alt","resin_url":"http://resin2:2260","admin_token":"...",
   "proxy_addr":"resin2:2260","proxy_token":"...","platform_id":"<uuid>"}
]
```

Every entry keeps taking one password — `EF_PROXY_PASSWORD`. Upstream tokens stay
in configuration and are never accepted from a client, so a leaked Resin token
does not open this entry.

With one instance a route key is the bare account, exactly as before. With
several, keys are `name/account`, and a client that pins selects the instance by
prefixing its proxy username:

- `opencode.lease1` — any instance holding `lease1`; `auto` routing when the
  request does not pin at all
- `alt/opencode.lease1` — that name on instance `alt` only

The qualifier matters because two instances can hold a lease of the same name;
without it the request could be served from the wrong Resin and fail with 401.

## Endpoints

- `GET /healthz` — 503 when no egress is available
- `GET /status` — per-route state, verdict, egress IP, last probe time

## Build

```sh
go test ./...
CGO_ENABLED=0 GOOS=linux go build -o egress-filter ./cmd/egress-filter
```

Images publish to `ghcr.io/heatonz/egress-filter` on `v*` tags.
