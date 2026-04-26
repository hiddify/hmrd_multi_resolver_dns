package multidns

import (
	"context"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// =====================================================================
// Fix #1 regression: caller-side context.Canceled must NOT be charged as
// a network failure. Before the fix, N caller cancellations could trip a
// healthy resolver into the down state.
// =====================================================================
func TestReviewFix_CanceledNotPenalized(t *testing.T) {
	// Upstream that hangs forever — every Resolve will only return when
	// the caller cancels.
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return nil })

	mgr := New(Options{
		DefaultDeadline:   2 * time.Second,
		DownAfterFailures: 3,
	})
	defer mgr.Close()
	id, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: up.Address(), Timeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 10 caller-cancellations. miekg/dns doesn't subscribe to ctx-cancel,
	// so each Resolve waits its per-attempt Timeout before returning — but
	// the attempt() guard must skip recording on Canceled.
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		_, _ = mgr.Resolve(ctx, newQ("a.example."))
		cancel()
	}

	if got := stateOf(mgr, id); got == "down" {
		t.Fatalf("resolver was marked down purely from caller cancellations")
	}
	stat := statByID(t, mgr, id)
	if stat.TimeoutCount != 0 || stat.InvalidCount != 0 {
		t.Fatalf("counters bumped on caller cancel: timeouts=%d invalid=%d",
			stat.TimeoutCount, stat.InvalidCount)
	}
}

// =====================================================================
// Fix #2 regression: with default Timeout (omitted by caller), a hung
// upstream must not consume the entire DefaultDeadline. The Manager must
// fail over to the next resolver well before the overall deadline ends.
// =====================================================================
func TestReviewFix_DefaultTimeoutAllowsFailover(t *testing.T) {
	dropper := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return nil })
	good := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.100") })

	mgr := New(Options{
		DefaultDeadline:        5 * time.Second,
		DefaultResolverTimeout: 200 * time.Millisecond,
	})
	defer mgr.Close()

	// Note: Timeout deliberately not set on either ResolverConfig.
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: dropper.Address()}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: good.Address()}); err != nil {
		t.Fatal(err)
	}

	// Drive enough queries that round-robin must put the dropper first at
	// least once. Every query must succeed within the per-attempt timeout
	// window plus a small slack — far less than DefaultDeadline.
	for i := 0; i < 6; i++ {
		start := time.Now()
		resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
		took := time.Since(start)
		if err != nil {
			t.Fatalf("iter %d: %v (took %v)", i, err, took)
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("iter %d: bad rcode %d", i, resp.Rcode)
		}
		// Even on the failover path: dropper consumes ~200ms then good
		// answers in <10ms; total should be well under 1s.
		if took > 1*time.Second {
			t.Fatalf("iter %d: failover too slow (%v) — Timeout default not applied", i, took)
		}
	}
}

// =====================================================================
// Fix #3 regression: in LowestLatency mode, a resolver added later (with
// no measured EWMA) must be sampled instead of being permanently shadowed
// by an established slow resolver.
// =====================================================================
func TestReviewFix_LowestLatencySamplesNewcomers(t *testing.T) {
	slow := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg {
		time.Sleep(20 * time.Millisecond)
		return reply(q, "192.0.2.110")
	})
	mgr := New(Options{
		DefaultDeadline:        500 * time.Millisecond,
		DefaultResolverTimeout: 200 * time.Millisecond,
		LoadBalance:            LBLowestLatency,
	})
	defer mgr.Close()

	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: slow.Address()}); err != nil {
		t.Fatal(err)
	}
	// Warm slow's EWMA so sortByLatency has a non-zero number to compare.
	for i := 0; i < 4; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("warm.example."))
	}

	// Now add a fresh upstream — its EWMA is 0.
	fresh := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.111") })
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: fresh.Address()}); err != nil {
		t.Fatal(err)
	}

	// Just one query is enough — fix says unmeasured sorts first, so the
	// next Resolve must hit `fresh`.
	beforeFresh := fresh.callsCount()
	if _, err := mgr.Resolve(context.Background(), newQ("probe.example.")); err != nil {
		t.Fatal(err)
	}
	if fresh.callsCount() == beforeFresh {
		t.Fatalf("LowestLatency starved newcomer: fresh upstream never sampled")
	}
}

// =====================================================================
// Fix #4 regression: weighted load balancing must approximate the
// configured weight ratio. With weights 9:1, the heavy resolver should
// receive roughly 90% of traffic over many trials.
// =====================================================================
func TestReviewFix_WeightedRespectsWeights(t *testing.T) {
	heavy := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.120") })
	light := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.121") })

	mgr := New(Options{
		DefaultDeadline:        500 * time.Millisecond,
		DefaultResolverTimeout: 200 * time.Millisecond,
		LoadBalance:            LBWeighted,
	})
	defer mgr.Close()

	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: heavy.Address(), Weight: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: light.Address(), Weight: 1}); err != nil {
		t.Fatal(err)
	}

	const trials = 400
	for i := 0; i < trials; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("w.example."))
	}

	heavyN := heavy.callsCount()
	lightN := light.callsCount()
	if heavyN == 0 || lightN == 0 {
		t.Fatalf("expected both to be hit at least once: heavy=%d light=%d", heavyN, lightN)
	}
	heavyFrac := float64(heavyN) / float64(trials)
	expected := 0.9
	if math.Abs(heavyFrac-expected) > 0.07 {
		t.Fatalf("weighted distribution off: heavy=%.2f%% expected ~%.0f%% (heavy=%d light=%d)",
			heavyFrac*100, expected*100, heavyN, lightN)
	}
	t.Logf("weighted split: heavy=%d (%.1f%%) light=%d (%.1f%%)",
		heavyN, heavyFrac*100, lightN, float64(lightN)/float64(trials)*100)
}

// Weight 0 must be treated as a pure fallback: only used if the weighted
// draw fails or every weighted candidate is unavailable.
func TestReviewFix_WeightedZeroIsFallback(t *testing.T) {
	primary := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.130") })
	fallback := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.131") })

	mgr := New(Options{
		DefaultDeadline:        500 * time.Millisecond,
		DefaultResolverTimeout: 200 * time.Millisecond,
		LoadBalance:            LBWeighted,
	})
	defer mgr.Close()

	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: primary.Address(), Weight: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: fallback.Address(), Weight: 0}); err != nil {
		t.Fatal(err)
	}

	const trials = 200
	for i := 0; i < trials; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("zw.example."))
	}

	if fallback.callsCount() != 0 {
		t.Fatalf("weight-0 fallback received traffic when primary was healthy: fallback=%d primary=%d",
			fallback.callsCount(), primary.callsCount())
	}
	if primary.callsCount() != int64(trials) {
		t.Fatalf("primary did not receive all traffic: primary=%d trials=%d",
			primary.callsCount(), trials)
	}
}

// =====================================================================
// Fix #5 regression: when every candidate is throttled (token bucket
// empty), the all-throttled fallback must send to *exactly one* upstream
// — not to all of them, which would defeat the rate-limit by N×.
// =====================================================================
func TestReviewFix_ThrottleFallbackSendsOnlyOne(t *testing.T) {
	// Two upstreams that always return REFUSED so they always stay in
	// rate_limited state with empty buckets.
	a := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return rcodeOnly(q, dns.RcodeRefused) })
	b := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return rcodeOnly(q, dns.RcodeRefused) })

	mgr := New(Options{
		DefaultDeadline:        300 * time.Millisecond,
		DefaultResolverTimeout: 100 * time.Millisecond,
		RateLimitFloorRPM:      6,
	})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: a.Address()}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: b.Address()}); err != nil {
		t.Fatal(err)
	}

	// Drive enough requests to enter rate_limited and burn the buckets.
	for i := 0; i < 12; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("warm.example."))
	}

	// Snapshot baseline.
	aBefore := a.callsCount()
	bBefore := b.callsCount()

	// Now do exactly one Resolve when both are throttled. Fix says only
	// ONE upstream should be hit by the fallback.
	_, _ = mgr.Resolve(context.Background(), newQ("rl.example."))
	aDelta := a.callsCount() - aBefore
	bDelta := b.callsCount() - bBefore

	if aDelta+bDelta != 1 {
		t.Fatalf("all-throttled fallback amplified: total hits this query = %d (a=%d b=%d), expected 1",
			aDelta+bDelta, aDelta, bDelta)
	}
}

// =====================================================================
// Fix #6 regression: the custom UDP dialer path must honor the query's
// EDNS0 UDPSize. With a 4096-byte buffer requested, a >512-byte response
// must arrive intact rather than being truncated by the default cap.
// =====================================================================
func TestReviewFix_CustomDialerHonorsEDNS0(t *testing.T) {
	// Upstream that returns a response with many TXT records — well over
	// 512 bytes total — and sets the response OPT to match.
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeSuccess
		// 30 TXT RRs of 60 bytes each ≈ 1800+ bytes — definitely > 512.
		for i := 0; i < 30; i++ {
			r.Answer = append(r.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				Txt: []string{"x-padding-payload-payload-payload-payload-payload-payload-z"},
			})
		}
		// Echo a reasonable OPT so the wire response advertises a buffer.
		r.SetEdns0(4096, false)
		return r
	})

	var dialed atomic.Int64
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	mgr := New(Options{
		DefaultDeadline:        2 * time.Second,
		DefaultResolverTimeout: 1 * time.Second,
	})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: up.Address(), Dialer: dial,
	}); err != nil {
		t.Fatal(err)
	}

	q := newQ("big.example.")
	q.SetEdns0(4096, false)

	resp, err := mgr.Resolve(context.Background(), q)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dialed.Load() == 0 {
		t.Fatalf("custom dialer was not invoked")
	}
	if len(resp.Answer) != 30 {
		t.Fatalf("response truncated: got %d answer RRs (want 30) — EDNS0 UDPSize not honored on custom dialer path",
			len(resp.Answer))
	}
	if resp.Truncated {
		t.Fatalf("response marked TC=1: server didn't fit even at 4096 — test assumption broken")
	}
}

// =====================================================================
// Quick concurrency safety check: the LBWeighted shuffle uses math/rand —
// drive concurrent traffic and make sure -race stays clean.
// =====================================================================
func TestReviewFix_WeightedConcurrent(t *testing.T) {
	a := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.140") })
	b := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.141") })

	mgr := New(Options{
		DefaultDeadline:        500 * time.Millisecond,
		DefaultResolverTimeout: 200 * time.Millisecond,
		LoadBalance:            LBWeighted,
	})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: a.Address(), Weight: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: b.Address(), Weight: 1}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var ok atomic.Int64
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				if _, err := mgr.Resolve(context.Background(), newQ("c.example.")); err == nil {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if ok.Load() == 0 {
		t.Fatalf("no successes")
	}
}
