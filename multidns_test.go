package multidns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockUpstream is a programmable stand-in for a real resolver.
type mockUpstream struct {
	mu       sync.Mutex
	respond  func(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
	calls    atomic.Int64
	closeErr error
}

func (m *mockUpstream) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m.calls.Add(1)
	m.mu.Lock()
	fn := m.respond
	m.mu.Unlock()
	if fn == nil {
		return okAnswer(q), nil
	}
	return fn(ctx, q)
}

func (m *mockUpstream) Close() error { return m.closeErr }

func (m *mockUpstream) setRespond(fn func(ctx context.Context, q *dns.Msg) (*dns.Msg, error)) {
	m.mu.Lock()
	m.respond = fn
	m.mu.Unlock()
}

func okAnswer(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = dns.RcodeSuccess
	return r
}

func refusedAnswer(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = dns.RcodeRefused
	return r
}

// addMock attaches a mockUpstream to the manager bypassing newUpstream so tests
// don't open real sockets. Holds m.mu like the real AddResolver, so the same
// lifecycle invariants are upheld (probeWG.Add cannot race with Close).
func addMock(t *testing.T, m *Manager, name string, mu *mockUpstream) string {
	t.Helper()
	cfg := ResolverConfig{
		Name:     name,
		Protocol: ProtoUDP,
		Address:  "mock",
		Timeout:  500 * time.Millisecond,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		// Lifecycle race tests deliberately add after Close; treat as a
		// no-op rather than failing.
		return ""
	}
	id := fmt.Sprintf("r-%d", m.idSeq.Add(1))
	rs := newResolverState(id, cfg, mu, &m.opts)
	m.pool.add(rs)
	m.startProbe(rs)
	return id
}

func newQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return q
}

func TestResolveSingleResolver(t *testing.T) {
	m := New(Options{DefaultDeadline: time.Second})
	defer m.Close()

	mu := &mockUpstream{}
	addMock(t, m, "a", mu)

	resp, err := m.Resolve(context.Background(), newQuery("example.com"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got %#v", resp)
	}
	if got := mu.calls.Load(); got != 1 {
		t.Fatalf("expected 1 call, got %d", got)
	}
}

func TestResolveFailoverOnError(t *testing.T) {
	m := New(Options{DefaultDeadline: time.Second})
	defer m.Close()

	bad := &mockUpstream{}
	bad.setRespond(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("dial failed")
	})
	good := &mockUpstream{}

	addMock(t, m, "bad", bad)
	addMock(t, m, "good", good)

	// Run several queries; round-robin guarantees the bad upstream is
	// selected at least once, exercising failover. Every query must succeed.
	for i := 0; i < 6; i++ {
		resp, err := m.Resolve(context.Background(), newQuery("example.com"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected success, got %d", resp.Rcode)
		}
	}
	if bad.calls.Load() < 1 || good.calls.Load() < 1 {
		t.Fatalf("expected both upstreams to be hit (bad=%d good=%d)", bad.calls.Load(), good.calls.Load())
	}
}

func TestResolveDeadlineHonored(t *testing.T) {
	m := New(Options{DefaultDeadline: 60 * time.Millisecond})
	defer m.Close()

	slow := &mockUpstream{}
	slow.setRespond(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return okAnswer(q), nil
		}
	})
	addMock(t, m, "slow", slow)

	start := time.Now()
	_, err := m.Resolve(context.Background(), newQuery("example.com"))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected deadline error")
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("call took too long: %v", elapsed)
	}
}

func TestRateLimitTriggersThrottle(t *testing.T) {
	m := New(Options{
		DefaultDeadline:   time.Second,
		RateLimitFloorRPM: 6,
	})
	defer m.Close()

	limited := &mockUpstream{}
	limited.setRespond(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		return refusedAnswer(q), nil
	})
	id := addMock(t, m, "limited", limited)

	// Drive enough successful "requests" then a REFUSED to trigger AIMD.
	for i := 0; i < 5; i++ {
		_, _ = m.Resolve(context.Background(), newQuery("example.com"))
	}

	stats := m.Stats()
	var seen *ResolverStat
	for i := range stats {
		if stats[i].ID == id {
			seen = &stats[i]
		}
	}
	if seen == nil {
		t.Fatalf("resolver not found in stats")
	}
	if seen.State != "rate_limited" {
		t.Fatalf("expected rate_limited, got %q", seen.State)
	}
	if seen.CurrentRPMCap == 0 {
		t.Fatalf("expected RPM cap to be set")
	}
}

func TestProberRecoversDownResolver(t *testing.T) {
	m := New(Options{
		DefaultDeadline:   200 * time.Millisecond,
		ProbeInterval:     30 * time.Millisecond,
		DownAfterFailures: 2,
	})
	defer m.Close()

	var failing atomic.Bool
	failing.Store(true)

	flappy := &mockUpstream{}
	flappy.setRespond(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		if failing.Load() {
			return nil, errors.New("network unreachable")
		}
		return okAnswer(q), nil
	})
	id := addMock(t, m, "flappy", flappy)

	// Push it past DownAfterFailures by issuing a few queries.
	for i := 0; i < 4; i++ {
		_, _ = m.Resolve(context.Background(), newQuery("example.com"))
	}

	if got := getStateByID(m, id); got != "down" {
		t.Fatalf("expected down, got %q", got)
	}

	// Heal the upstream and let the prober pick it up.
	failing.Store(false)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if getStateByID(m, id) == "healthy" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("prober did not transition to healthy in time, state=%q", getStateByID(m, id))
}

func TestAddRemoveResolver(t *testing.T) {
	m := New(Options{DefaultDeadline: 200 * time.Millisecond})
	defer m.Close()

	mu := &mockUpstream{}
	id := addMock(t, m, "x", mu)

	if len(m.Resolvers()) != 1 {
		t.Fatalf("expected 1 resolver")
	}
	if err := m.RemoveResolver(id); err != nil {
		t.Fatalf("RemoveResolver: %v", err)
	}
	if len(m.Resolvers()) != 0 {
		t.Fatalf("expected 0 resolvers after remove")
	}
	if _, err := m.Resolve(context.Background(), newQuery("example.com")); err == nil {
		t.Fatalf("expected error from empty pool")
	}
}

func TestNoResolversError(t *testing.T) {
	m := New(Options{})
	defer m.Close()
	_, err := m.Resolve(context.Background(), newQuery("x.test"))
	if !errors.Is(err, ErrNoResolvers) {
		t.Fatalf("expected ErrNoResolvers, got %v", err)
	}
}

func TestBadResponseDoesNotPenalise(t *testing.T) {
	m := New(Options{DefaultDeadline: 200 * time.Millisecond})
	defer m.Close()

	mu := &mockUpstream{}
	mu.setRespond(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeFormatError
		return r, nil
	})
	id := addMock(t, m, "x", mu)

	for i := 0; i < 5; i++ {
		_, _ = m.Resolve(context.Background(), newQuery("x.test"))
	}
	if got := getStateByID(m, id); got != "healthy" {
		t.Fatalf("expected healthy after FormErr, got %q", got)
	}
}

func getStateByID(m *Manager, id string) string {
	for _, s := range m.Stats() {
		if s.ID == id {
			return s.State
		}
	}
	return ""
}

func TestSlidingCounter(t *testing.T) {
	var c slidingCounter
	now := time.Unix(1700000000, 0)
	c.add(now, 3)
	c.add(now.Add(2*time.Second), 5)
	if got := c.sum(now.Add(2 * time.Second)); got != 8 {
		t.Fatalf("sum: got %d want 8", got)
	}
	if got := c.sum(now.Add(70 * time.Second)); got != 0 {
		t.Fatalf("expired sum: got %d want 0", got)
	}
}

func TestTokenBucket(t *testing.T) {
	tb := newTokenBucket(60) // 1 per second
	now := time.Unix(1700000000, 0)
	consumed := 0
	for i := 0; i < 100; i++ {
		if tb.tryAcquire(now) {
			consumed++
		}
	}
	if consumed == 0 || consumed > 30 {
		t.Fatalf("expected modest burst, got %d", consumed)
	}
	// After 60s we should be able to drain another full bucket.
	consumed2 := 0
	for i := 0; i < 100; i++ {
		if tb.tryAcquire(now.Add(60 * time.Second)) {
			consumed2++
		}
	}
	if consumed2 == 0 {
		t.Fatalf("refill did not happen")
	}
}

func TestUncappedBucket(t *testing.T) {
	tb := newTokenBucket(0)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if !tb.tryAcquire(now) {
			t.Fatalf("uncapped bucket should always permit")
		}
	}
}
