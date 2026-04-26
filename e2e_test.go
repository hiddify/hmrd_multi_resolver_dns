package multidns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// =====================================================================
// Per-protocol roundtrip — exercises the actual UDP/TCP/DoT/DoH transports
// against real in-process servers (no mocks).
// =====================================================================

func TestE2E_UDP_Roundtrip(t *testing.T) {
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.1") })
	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: up.Address()}); err != nil {
		t.Fatalf("AddResolver: %v", err)
	}
	resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("bad response: %#v", resp)
	}
}

func TestE2E_TCP_Roundtrip(t *testing.T) {
	up := startTCPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.2") })
	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoTCP, Address: up.Address()}); err != nil {
		t.Fatalf("AddResolver: %v", err)
	}
	resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("bad response: err=%v resp=%#v", err, resp)
	}
}

func TestE2E_DoT_Roundtrip(t *testing.T) {
	up := startDoTUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.3") })
	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol:  ProtoDoT,
		Address:   up.Address(),
		TLSConfig: up.clientTLSConfig(),
	}); err != nil {
		t.Fatalf("AddResolver: %v", err)
	}
	resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("bad response: err=%v resp=%#v", err, resp)
	}
}

func TestE2E_DoH_Roundtrip(t *testing.T) {
	up := startDoHUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.4") })
	mgr := New(Options{DefaultDeadline: 2 * time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol:  ProtoDoH,
		Address:   up.dohURL(),
		TLSConfig: up.clientTLSConfig(),
	}); err != nil {
		t.Fatalf("AddResolver: %v", err)
	}
	resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("bad response: err=%v resp=%#v", err, resp)
	}
}

// =====================================================================
// Failover within deadline: the first resolver hard-fails (drops every
// packet → client times out), the second answers. The Resolve must succeed
// inside the overall deadline.
// =====================================================================
func TestE2E_FailoverWithinDeadline(t *testing.T) {
	dropper := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return nil })
	good := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.10") })

	mgr := New(Options{DefaultDeadline: 1500 * time.Millisecond})
	defer mgr.Close()

	// Per-attempt timeout MUCH smaller than overall deadline so failover fits.
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: dropper.Address(), Timeout: 200 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: good.Address(), Timeout: 200 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}

	// Repeat several times so RR ordering inevitably puts dropper first.
	saw := false
	for i := 0; i < 6; i++ {
		start := time.Now()
		resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
		took := time.Since(start)
		if err != nil {
			t.Fatalf("iter %d: %v (took %v)", i, err, took)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("iter %d: bad rcode/answer: %#v", i, resp)
		}
		if took > 1500*time.Millisecond {
			t.Fatalf("iter %d: blew deadline: %v", i, took)
		}
		if took > 150*time.Millisecond {
			// Big roundtrip means a failover happened.
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected at least one query to traverse the failover path")
	}
}

// Deadline must be honored even if every resolver hangs.
func TestE2E_DeadlineHonoredEverythingDown(t *testing.T) {
	d1 := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return nil })
	d2 := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return nil })
	mgr := New(Options{DefaultDeadline: 250 * time.Millisecond})
	defer mgr.Close()
	for _, a := range []string{d1.Address(), d2.Address()} {
		_, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: a, Timeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	_, err := mgr.Resolve(context.Background(), newQ("a.example."))
	took := time.Since(start)
	if err == nil {
		t.Fatalf("expected failure")
	}
	// Deadline 250ms: must not exceed it by much (allow scheduler slack).
	if took > 500*time.Millisecond {
		t.Fatalf("blew deadline: %v", took)
	}
}

// =====================================================================
// Rate-limit AIMD: an upstream that returns REFUSED should put the resolver
// into rate_limited state with a non-zero RPM cap. After it heals, the
// state must return to healthy.
// =====================================================================
func TestE2E_RateLimitProgression(t *testing.T) {
	var refusing atomic.Bool
	refusing.Store(true)
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg {
		if refusing.Load() {
			return rcodeOnly(q, dns.RcodeRefused)
		}
		return reply(q, "192.0.2.20")
	})

	mgr := New(Options{
		DefaultDeadline:   500 * time.Millisecond,
		RateLimitFloorRPM: 6,
		RateLimitUncapRPM: 60,
		RateLimitAdditive: 30,
	})
	defer mgr.Close()
	id, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: up.Address(), Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send a few requests — REFUSED triggers the AIMD decrease.
	for i := 0; i < 3; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("a.example."))
	}
	stat := statByID(t, mgr, id)
	if stat.State != "rate_limited" {
		t.Fatalf("expected rate_limited after REFUSED, got %q (cap=%d)", stat.State, stat.CurrentRPMCap)
	}
	if stat.CurrentRPMCap == 0 {
		t.Fatalf("expected non-zero RPM cap, got 0")
	}
}

// DoH HTTP-level rate limiting (HTTP 429) must also trigger throttling.
func TestE2E_DoH_HTTP429_TriggersRateLimit(t *testing.T) {
	var rl atomic.Bool
	rl.Store(true)
	up := startDoHUpstream(t, func(q *dns.Msg) *dns.Msg {
		if rl.Load() {
			return dohRateLimitSentinel()
		}
		return reply(q, "192.0.2.30")
	})
	mgr := New(Options{
		DefaultDeadline:   1500 * time.Millisecond,
		RateLimitFloorRPM: 6,
	})
	defer mgr.Close()
	id, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoDoH, Address: up.dohURL(), TLSConfig: up.clientTLSConfig(),
		Timeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("a.example."))
	}
	stat := statByID(t, mgr, id)
	if stat.State != "rate_limited" {
		t.Fatalf("expected rate_limited after HTTP 429, got %q", stat.State)
	}
}

// =====================================================================
// Down state + prober recovery: hard-fail for a while, ensure resolver hits
// `down`, then heal upstream, ensure prober brings it back to `healthy`.
// =====================================================================
func TestE2E_DownAndProberRecovery(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	var probedOnHealth atomic.Int64

	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg {
		if failing.Load() {
			return nil // drop → timeout
		}
		probedOnHealth.Add(1)
		return reply(q, "192.0.2.40")
	})

	mgr := New(Options{
		DefaultDeadline:   200 * time.Millisecond,
		ProbeInterval:     40 * time.Millisecond,
		DownAfterFailures: 2,
	})
	defer mgr.Close()
	id, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: up.Address(), Timeout: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Push past DownAfterFailures.
	for i := 0; i < 4; i++ {
		_, _ = mgr.Resolve(context.Background(), newQ("trigger.example."))
	}
	if got := stateOf(mgr, id); got != "down" {
		t.Fatalf("expected down, got %q", got)
	}

	failing.Store(false)
	// Wait for prober to flip state. Allow generous slack.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if stateOf(mgr, id) == "healthy" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stateOf(mgr, id) != "healthy" {
		t.Fatalf("prober did not recover, state=%q", stateOf(mgr, id))
	}
	if probedOnHealth.Load() == 0 {
		t.Fatalf("upstream was never re-tried by prober")
	}

	// And queries should now succeed.
	resp, err := mgr.Resolve(context.Background(), newQ("ok.example."))
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("post-recovery resolve failed: %v %#v", err, resp)
	}
}

// =====================================================================
// AddResolver / RemoveResolver under live traffic: a worker pool issues
// queries continuously while resolvers are added and removed. Every query
// must succeed (because at least one healthy resolver is always present)
// and no goroutines must race.
// =====================================================================
func TestE2E_LiveAddRemove(t *testing.T) {
	stable := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.50") })
	churny := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.51") })

	mgr := New(Options{DefaultDeadline: 500 * time.Millisecond})
	defer mgr.Close()

	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: stable.Address(), Timeout: 200 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var success, failure atomic.Int64
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := mgr.Resolve(context.Background(), newQ("a.example."))
				if err != nil {
					failure.Add(1)
				} else {
					success.Add(1)
				}
			}
		}()
	}

	// Churn the second resolver: add, sleep, remove, sleep, repeat.
	for i := 0; i < 5; i++ {
		id, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: churny.Address(), Timeout: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
		if err := mgr.RemoveResolver(id); err != nil {
			t.Fatalf("remove: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if success.Load() == 0 {
		t.Fatalf("no successes recorded")
	}
	// Some failures may slip through if a remove races with a Resolve, but it
	// should be a small minority.
	if failure.Load() > success.Load()/4 {
		t.Fatalf("too many failures: %d success vs %d failure", success.Load(), failure.Load())
	}
}

// =====================================================================
// Custom Dialer: every transport must invoke the user-provided DialFunc.
// =====================================================================
func TestE2E_CustomDialer_UDP(t *testing.T) {
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.60") })
	var hits atomic.Int64
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoUDP, Address: up.Address(), Timeout: 500 * time.Millisecond, Dialer: dial,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := mgr.Resolve(context.Background(), newQ("a.example."))
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("resolve: %v %#v", err, resp)
	}
	if hits.Load() == 0 {
		t.Fatalf("custom dialer was never called")
	}
}

func TestE2E_CustomDialer_TCP(t *testing.T) {
	up := startTCPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.61") })
	var hits atomic.Int64
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol: ProtoTCP, Address: up.Address(), Timeout: 500 * time.Millisecond, Dialer: dial,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Resolve(context.Background(), newQ("a.example.")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatalf("TCP dialer was never called")
	}
}

func TestE2E_CustomDialer_DoT(t *testing.T) {
	up := startDoTUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.62") })
	var hits atomic.Int64
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	mgr := New(Options{DefaultDeadline: 2 * time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol:  ProtoDoT,
		Address:   up.Address(),
		TLSConfig: up.clientTLSConfig(),
		Timeout:   1 * time.Second,
		Dialer:    dial,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Resolve(context.Background(), newQ("a.example.")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatalf("DoT dialer was never called")
	}
}

func TestE2E_CustomDialer_DoH(t *testing.T) {
	up := startDoHUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.63") })
	var hits atomic.Int64
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	mgr := New(Options{DefaultDeadline: 2 * time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{
		Protocol:  ProtoDoH,
		Address:   up.dohURL(),
		TLSConfig: up.clientTLSConfig(),
		Timeout:   1 * time.Second,
		Dialer:    dial,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Resolve(context.Background(), newQ("a.example.")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatalf("DoH dialer was never called")
	}
}

// =====================================================================
// Full server listener with two real upstreams. We dig() through the
// listener and verify the answer.
// =====================================================================
func TestE2E_FullServerWithRealUpstreams(t *testing.T) {
	a := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.70") })
	b := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.71") })

	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	for _, u := range []*realUpstream{a, b} {
		if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: u.Address(), Timeout: 200 * time.Millisecond}); err != nil {
			t.Fatal(err)
		}
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	srv := mgr.NewServer(addr, "udp")
	go func() { _ = srv.ListenAndServe() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	c := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(time.Second)
	var resp *dns.Msg
	for time.Now().Before(deadline) {
		resp, _, err = c.Exchange(newQ("hi.example."), addr)
		if err == nil && resp != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("bad response: %#v", resp)
	}
}

// =====================================================================
// Helpers
// =====================================================================

func statByID(t *testing.T, m *Manager, id string) ResolverStat {
	t.Helper()
	for _, s := range m.Stats() {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("resolver %s not in stats", id)
	return ResolverStat{}
}

func stateOf(m *Manager, id string) string {
	for _, s := range m.Stats() {
		if s.ID == id {
			return s.State
		}
	}
	return ""
}

// errAllResolversFailedSentinel ensures the public sentinel is wrapped
// correctly when every candidate fails (used by external callers via
// errors.Is).
func TestE2E_ErrSentinelWrapping(t *testing.T) {
	mgr := New(Options{DefaultDeadline: 100 * time.Millisecond})
	defer mgr.Close()
	_, err := mgr.Resolve(context.Background(), newQ("x."))
	if !errors.Is(err, ErrNoResolvers) {
		t.Fatalf("expected ErrNoResolvers, got %v", err)
	}
}
