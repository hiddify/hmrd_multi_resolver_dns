# hmrd_multi_resolver_dns

A standalone Go library that wraps a configurable set of upstream DNS
resolvers (UDP, TCP, DoT, DoH) behind one intelligent dispatcher. It is
designed to be embedded in [hiddify-sing-box][singbox] (and through it,
[hiddify-core][core]) as a more capable replacement for the current
single-upstream code path.

[singbox]: https://github.com/hiddify/hiddify-sing-box
[core]: https://github.com/hiddify/hiddify-core

## Why this exists

Real-world resolvers go down, get rate-limited, and recover. A fixed
primary/secondary scheme — or a static round-robin — wastes the caller's
deadline on a hung primary, ignores rate-limit signals, and never learns
when a failed upstream is healthy again.

This library makes those concerns first-class:

- Per-query retry on the next resolver while strictly respecting
  `ctx.Deadline`.
- Failure classifier feeds an **AIMD throttle** per resolver; rate-limit
  signals (`REFUSED`, `SERVFAIL`, HTTP 429) cut the cap, sustained success
  grows it back. No operator pre-tuning.
- Down resolvers get **probed in the background** with the very query
  that triggered the outage — cheapest way to detect recovery without
  polluting live traffic.
- Every transport accepts a custom `DialFunc`, so an embedder (e.g.
  hiddify-sing-box) can route DNS through a tunnel.

The reference implementation that inspired several mechanics
(Rcode-based rate-limit detection, decaying counters, probing unhealthy
resolvers) is [vaydns PR #64][vaydns], but `vaydns.MultiResolver` is a
`net.PacketConn` bolted onto a single tunnel. This library is a
first-class DNS proxy with per-query semantics.

[vaydns]: https://github.com/net2share/vaydns/pull/64

## Features

| Feature | Where |
|---|---|
| UDP / TCP / DoT / DoH upstreams | `resolver.go` |
| Deadline-aware retry across candidates | `pool.go` |
| AIMD rate-limit throttling per resolver | `health.go`, `ratelimit.go` |
| Background recovery probing using the failing query | `prober.go` |
| Round-robin / weighted / lowest-latency LB strategies | `pool.go` |
| Dynamic `AddResolver` / `RemoveResolver` at runtime | `multidns.go` |
| Custom `DialFunc` injection on every transport | `resolver.go` |
| Optional UDP+TCP DNS server listener | `server.go` |
| `net.PacketConn` surface for DNS-tunnel integrations | `packetconn.go` |

## Install

```bash
go get github.com/hiddify/hmrd_multi_resolver_dns
```

Requires Go 1.25+. Wire format via [`miekg/dns`][miekg].

[miekg]: https://github.com/miekg/dns

## Usage — programmatic

```go
import (
    "context"
    "log"

    "github.com/miekg/dns"
    multidns "github.com/hiddify/hmrd_multi_resolver_dns"
)

mgr := multidns.New(multidns.Options{
    DefaultDeadline:        5 * time.Second, // overall query deadline
    DefaultResolverTimeout: 2 * time.Second, // per-attempt cap (failover budget)
    LoadBalance:            multidns.LBRoundRobin,
    ProbeInterval:          5 * time.Second,
})
defer mgr.Close()

mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoUDP,
    Address:  "1.1.1.1:53",
})
mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoDoH,
    Address:  "https://cloudflare-dns.com/dns-query",
})
mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoDoT,
    Address:  "1.1.1.1:853",
})

q := new(dns.Msg)
q.SetQuestion("example.com.", dns.TypeA)
resp, err := mgr.Resolve(context.Background(), q)
if err != nil {
    log.Fatal(err)
}
log.Printf("got %d answers", len(resp.Answer))
```

## Usage — built-in DNS server

```go
mgr := multidns.New(multidns.Options{ /* ... */ })
mgr.AddResolver( /* ... */ )

srv := mgr.NewServer(":5353") // UDP+TCP by default; pass "udp" or "tcp" to limit
go srv.ListenAndServe()
defer srv.Shutdown(context.Background())
```

Then `dig @127.0.0.1 -p 5353 example.com` resolves through the pool.

A runnable demo CLI lives at [`example/main.go`](example/main.go):

```bash
go run ./example \
    -listen :5353 \
    -upstream udp://1.1.1.1:53 \
    -upstream udp://8.8.8.8:53 \
    -upstream dot://1.1.1.1:853 \
    -upstream doh://https://cloudflare-dns.com/dns-query \
    -stats 5s
```

## Usage — as a `net.PacketConn` for DNS-tunnel protocols

DNS-tunnel protocols like [dnstt](https://github.com/net2share/vaydns) (used by hiddify) speak raw DNS wire format to a recursive resolver and care most about *delivery reliability* — if the resolver they're using gets rate-limited or blocked, the whole tunnel stalls. The library exposes its smart pool as a `net.PacketConn` so it can drop in wherever such a protocol expects one:

```go
mgr := multidns.New(multidns.Options{ /* ... */ })
mgr.AddResolver( /* recursive resolver A */ )
mgr.AddResolver( /* recursive resolver B */ )
mgr.AddResolver( /* recursive resolver C */ )

conn := mgr.PacketConn()                // implements net.PacketConn
defer conn.Close()                      // does NOT close mgr — caller owns mgr

// hand `conn` to the tunnel/protocol that wants a net.PacketConn
tunnel.SetResolverConn(conn)
```

Semantics: `WriteTo(buf, _)` unpacks `buf` as a DNS query and dispatches it asynchronously through the pool (smart selection, AIMD throttling, recovery probing all apply). The response — when one comes — surfaces on the next `ReadFrom`. `SetReadDeadline` / `SetWriteDeadline` are honored. Closing the conn does not close the underlying Manager, so direct `Resolve` calls and other PacketConns can keep using the same pool.

## Usage — embedded with a custom Dialer

This is the integration point for hiddify-sing-box. Each resolver can
carry its own `DialFunc`, which is wired into the transport (UDP/TCP/DoT
get it via `dns.Client.Dialer`; DoH gets it via the `http.Transport.DialContext`).

```go
import "github.com/sagernet/sing/common/network"

mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoUDP,
    Address:  "1.1.1.1:53",
    Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
        // Route DNS through a sing-box outbound, an SSH tunnel, a SOCKS5
        // proxy — whatever produces a net.Conn for (network, addr).
        return tunneledDial(ctx, network, addr)
    },
})
```

## Configuration reference

### `Options`

| Field | Default | Notes |
|---|---|---|
| `DefaultDeadline` | 5s | Applied when the caller's `ctx` has no deadline. |
| `DefaultResolverTimeout` | 2s | Per-attempt cap. Smaller than `DefaultDeadline` so failover fits inside one query. |
| `LoadBalance` | `LBRoundRobin` | `LBRoundRobin` / `LBWeighted` / `LBLowestLatency`. |
| `ProbeInterval` | 5s | How often a `down` resolver is re-tried with its failing query. |
| `DownAfterFailures` | 8 | Consecutive timeout/network failures before a resolver is moved to `down`. |
| `RateLimitFloorRPM` | 6 | Hard floor for the AIMD cap. |
| `RateLimitUncapRPM` | 600 | Cap above this is treated as "uncapped". |
| `RateLimitAdditive` | 5 | Per-minute additive increase under sustained success. |
| `Logger` | no-op | Adapter to your logging system; `log/slog`-friendly shape. |

### `ResolverConfig`

| Field | Notes |
|---|---|
| `Protocol` | `ProtoUDP` \| `ProtoTCP` \| `ProtoDoT` \| `ProtoDoH`. |
| `Address` | `host:port` for UDP/TCP/DoT; full `https://` URL for DoH. |
| `Timeout` | Per-attempt cap; falls back to `Options.DefaultResolverTimeout`. |
| `TLSConfig` | DoT/DoH only. SNI is auto-derived from `Address` if unset. |
| `Dialer` | Optional `DialFunc` for routing through a tunnel. |
| `Weight` | `LBWeighted` only; `0` ⇒ pure fallback. |
| `Name` | Optional friendly id surfaced in stats. |
| `InitialRPM` | Optional starting throttle cap; `0` ⇒ uncapped. |

## How it decides things

1. **Selecting a candidate.** `pool.candidates()` snapshots the current
   resolvers, drops anything in `down`, and orders the rest per
   `LoadBalance`. `LBLowestLatency` prefers unmeasured resolvers first
   (so newcomers get sampled), then ascending EWMA. `LBWeighted` runs a
   weighted random shuffle; weight 0 means pure fallback.
2. **Sending.** Each candidate's token bucket gates throughput at
   `currentRPMCap` (0 = uncapped). If the bucket rejects, the pool moves
   to the next candidate. If every candidate is throttled, we force
   exactly one through — never N — so AIMD isn't amplified by N×.
3. **Per-attempt timeout.** `min(ResolverConfig.Timeout, ctx.deadline-now)`
   is applied so a hung resolver can't burn the whole query budget.
4. **Classifying the result.** `failNone` / `failTimeout` / `failNetwork`
   / `failRateLimit` / `failBadResponse`. `failBadResponse` (e.g.
   `FormErr` from the upstream) does **not** penalize the resolver.
   `failRateLimit` triggers AIMD multiplicative-decrease on the cap.
   N consecutive `failTimeout`/`failNetwork` push the resolver to `down`
   and stash the offending query.
5. **Recovery.** A per-resolver goroutine wakes every `ProbeInterval`
   while the resolver is `down`, replays the stashed query (off the hot
   path, bypassing the bucket). On a valid response the cap resets to 0
   and state returns to `healthy`.

## Testing

```bash
go test -race -count=1 ./...   # 39 tests, ~3s wall clock
go vet ./...
```

Coverage includes:

- Per-protocol roundtrips against real in-process UDP/TCP/DoT/DoH
  servers (self-signed certs).
- Failover within a tight overall deadline, with one upstream that
  drops every packet.
- Rate-limit AIMD progression (Rcode REFUSED) and DoH HTTP-429.
- Down → prober → healthy cycle, verifying the prober uses the failing
  query.
- `AddResolver` / `RemoveResolver` under live traffic.
- Custom `DialFunc` invoked on every transport (UDP/TCP/DoT/DoH).
- Concurrent lifecycle stress (`AddResolver` ↔ `Close` 50× under -race).
- All six findings from the initial code review have a regression test
  in [`review_fixes_test.go`](review_fixes_test.go).

## Status

Pre-1.0 — API may shift before the first tagged release. The shapes most
likely to change: `Options` field names and the `Logger` interface (to
align with whatever the embedder uses).

## License

TBD — match the parent project's license once selected.
