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
socks5h://opencode.freeproxy30:any@egress-filter:1080
http://opencode.auto:any@egress-filter:1080
```

## Passive only

There is no active prober. Probing would consume the same upstream quota the
real requests need, and its results are polluted by the rate limiting it causes.
Evidence comes from traffic that was going to be sent anyway.

Each response is classified into three outcomes, not two:

- **200** — the egress works; clears failures
- **403 with a block message** — the egress is refused; counts toward withdrawal
- **403 with a shape message, 400, 429, 5xx** — no evidence about the egress

That third case is the important one. `403 can only be used from within OpenCode`
means the request shape is wrong, and `context_length_exceeded` (a 400) means the
conversation is too long. Neither says anything about the egress, and treating
either as a failure drains the pool for nothing.

## Withdrawal

After `EF_FAIL_THRESHOLD` consecutive blocked responses the route is withheld,
and its lease binding is deleted so Resin re-allocates it. Deletion is
rate-limited per account (`EF_EVICT_COOLDOWN`) so one noisy window cannot churn
the same lease repeatedly.

Eviction is **off by default**. Run a while with `EF_EVICT=false` and read
`/status` before enabling it.

## Configuration

| variable | default | meaning |
| --- | --- | --- |
| `EF_RESIN_URL` | `http://resin:2260` | Resin control plane and proxy |
| `EF_RESIN_TOKEN` | — | admin token, required |
| `EF_PLATFORM_ID` | — | platform UUID, required |
| `EF_PLATFORM` | `opencode` | platform name used in the path and SOCKS username |
| `EF_PROXY_TOKEN` | — | Resin proxy token used in the path |
| `EF_LISTEN_REVERSE` | `:8080` | reverse entry |
| `EF_LISTEN_FORWARD` | `:1080` | forward entry |
| `EF_LISTEN_STATUS` | `:9090` | `/healthz`, `/status` |
| `EF_DISCOVERY_INTERVAL` | `60s` | lease refresh |
| `EF_FAIL_THRESHOLD` | `2` | blocked responses before withdrawal |
| `EF_EVICT` | `false` | delete leases of blocked routes |
| `EF_EVICT_COOLDOWN` | `10m` | minimum gap between deletions of one account |

## Endpoints

- `GET /healthz` — 503 when no egress is available
- `GET /status` — per-route state, verdict, egress IP, last probe time

## Build

```sh
go test ./...
CGO_ENABLED=0 GOOS=linux go build -o egress-filter ./cmd/egress-filter
```

Images publish to `ghcr.io/heatonz/egress-filter` on `v*` tags.
