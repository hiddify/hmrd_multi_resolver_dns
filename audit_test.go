package multidns

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestAudit_AddResolverCloseRace stresses the lifecycle: AddResolver and
// Close can collide in goroutines. Before the fix, the probeWG.Add(1) inside
// startProbe could race against Close's probeWG.Wait() and panic with
// "WaitGroup misuse: Add called concurrently with Wait". This test runs the
// scenario many times — under -race nothing must panic and no data race
// must surface.
func TestAudit_AddResolverCloseRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		mgr := New(Options{DefaultDeadline: 100 * time.Millisecond})

		var wg sync.WaitGroup
		// Two adders.
		for w := 0; w < 2; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 5; j++ {
					mu := &mockUpstream{}
					addMock(t, mgr, "x", mu)
				}
			}()
		}
		// One closer.
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%5) * time.Millisecond)
			_ = mgr.Close()
		}()
		wg.Wait()
		// One more Close to verify idempotency.
		_ = mgr.Close()
	}
}

// TestAudit_LowestLatency exercises the LBLowestLatency selector while
// concurrently driving traffic — the comparator must read latency without
// triggering a data race. This is the path that previously read
// `rs.latencyEWMA` without holding rs.mu.
func TestAudit_LowestLatency(t *testing.T) {
	a := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.80") })
	b := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg {
		// b is slower; sleep briefly to push latency EWMA up.
		time.Sleep(15 * time.Millisecond)
		return reply(q, "192.0.2.81")
	})

	mgr := New(Options{
		DefaultDeadline: 500 * time.Millisecond,
		LoadBalance:     LBLowestLatency,
	})
	defer mgr.Close()

	for _, u := range []*realUpstream{a, b} {
		if _, err := mgr.AddResolver(ResolverConfig{
			Protocol: ProtoUDP, Address: u.Address(), Timeout: 200 * time.Millisecond,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Warm up so EWMAs are non-zero on both.
	for i := 0; i < 4; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("warm.example."))
	}

	// Drive concurrent traffic — comparator runs frequently.
	var wg sync.WaitGroup
	var ok atomic.Int64
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				resp, err := mgr.Resolve(context.Background(), newQ("audit.example."))
				if err == nil && resp.Rcode == dns.RcodeSuccess {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if ok.Load() == 0 {
		t.Fatalf("no successful resolves under LowestLatency")
	}

	// Verify the faster upstream got more traffic. Allow some slack.
	stats := mgr.Stats()
	var fast, slow int64
	for _, s := range stats {
		switch s.Name {
		case "udp://" + a.Address():
			fast = s.ValidCount
		case "udp://" + b.Address():
			slow = s.ValidCount
		}
	}
	if fast == 0 {
		t.Fatalf("fast upstream never selected (fast=%d slow=%d)", fast, slow)
	}
	// LBLowestLatency may starve the slower upstream entirely once its EWMA
	// is established — that's the strategy working as intended. We only
	// require fast to dominate.
	if fast <= slow {
		t.Fatalf("LowestLatency did not prefer the fast upstream: fast=%d slow=%d", fast, slow)
	}
	t.Logf("LowestLatency split: fast=%d slow=%d", fast, slow)
}

// TestAudit_ConcurrentResolveDuringRemove makes sure that removing a
// resolver mid-Resolve never strands the caller — the next candidate in the
// pool should pick up the slack.
func TestAudit_ConcurrentResolveDuringRemove(t *testing.T) {
	stable := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.90") })
	churn := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.91") })

	mgr := New(Options{DefaultDeadline: 400 * time.Millisecond})
	defer mgr.Close()

	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: stable.Address(), Timeout: 200 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var success, failure atomic.Int64
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := mgr.Resolve(context.Background(), newQ("a.example.")); err != nil {
					failure.Add(1)
				} else {
					success.Add(1)
				}
			}
		}()
	}

	// Repeatedly add then remove the churn resolver.
	for i := 0; i < 8; i++ {
		id, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: churn.Address(), Timeout: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if err := mgr.RemoveResolver(id); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if success.Load() == 0 {
		t.Fatalf("no successes recorded during churn")
	}
	// Stable is always present, so failures should be near-zero. Allow a
	// tiny margin for races where the candidate list snapshot already moved
	// past stable before the next Resolve started.
	if failure.Load() > success.Load()/50 {
		t.Fatalf("too many failures during churn: %d success vs %d failure", success.Load(), failure.Load())
	}
}
