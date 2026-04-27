package multidns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestPacketConn_RoundTrip verifies the full async path: WriteTo → pool
// dispatch → ReadFrom returns the wire-format response. This is the
// integration shape vaydns/dnstt expects.
func TestPacketConn_RoundTrip(t *testing.T) {
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.200") })

	mgr := New(Options{DefaultDeadline: time.Second})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: up.Address(), Timeout: 200 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	pc := mgr.PacketConn()
	defer pc.Close()

	q := newQ("a.example.")
	q.Id = 0xBEEF
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	n, err := pc.WriteTo(wire, nil)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(wire) {
		t.Fatalf("WriteTo wrote %d, want %d", n, len(wire))
	}

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	rn, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:rn]); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("bad response: %#v", resp)
	}
	if resp.Id != 0xBEEF {
		t.Fatalf("response Id = %#x, want 0xBEEF", resp.Id)
	}
}

// TestPacketConn_FailoverPreserved verifies the smart pool's failover still
// applies when traffic goes through the PacketConn surface — this is the
// reason we built this surface (vaydns/dnstt's resolver becomes resilient).
func TestPacketConn_FailoverPreserved(t *testing.T) {
	dropper := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return nil })
	good := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.201") })

	mgr := New(Options{DefaultDeadline: 1500 * time.Millisecond, DefaultResolverTimeout: 200 * time.Millisecond})
	defer mgr.Close()

	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: dropper.Address()}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: good.Address()}); err != nil {
		t.Fatal(err)
	}

	pc := mgr.PacketConn()
	defer pc.Close()

	q := newQ("ok.example.")
	wire, _ := q.Pack()

	got := 0
	for i := 0; i < 4; i++ {
		if _, err := pc.WriteTo(wire, nil); err != nil {
			t.Fatal(err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 4096)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err == nil && resp.Rcode == dns.RcodeSuccess {
			got++
		}
	}
	if got == 0 {
		t.Fatalf("expected at least one successful response across 4 writes — failover not working through PacketConn")
	}
}

// TestPacketConn_RateLimitProgression verifies that signals from PacketConn
// traffic still drive the AIMD throttle on the underlying resolverState —
// proving the smart-pool semantics are not bypassed by the wire-format
// surface.
func TestPacketConn_RateLimitProgression(t *testing.T) {
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return rcodeOnly(q, dns.RcodeRefused) })

	mgr := New(Options{
		DefaultDeadline:        time.Second,
		DefaultResolverTimeout: 200 * time.Millisecond,
		RateLimitFloorRPM:      6,
	})
	defer mgr.Close()
	id, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: up.Address()})
	if err != nil {
		t.Fatal(err)
	}

	pc := mgr.PacketConn()
	defer pc.Close()

	q := newQ("rl.example.")
	wire, _ := q.Pack()
	for i := 0; i < 5; i++ {
		_, _ = pc.WriteTo(wire, nil)
		_ = pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		buf := make([]byte, 4096)
		_, _, _ = pc.ReadFrom(buf)
	}

	// Brief grace period — ReadFrom returns once the response is dispatched,
	// and record() runs inside Resolve. Just be patient about scheduling.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if statByID(t, mgr, id).State == "rate_limited" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected rate_limited via PacketConn traffic, got %q", statByID(t, mgr, id).State)
}

// TestPacketConn_ReadDeadline verifies SetReadDeadline triggers a timeout
// when no responses arrive — important so vaydns's tunnel can detect a
// stalled resolver and react.
func TestPacketConn_ReadDeadline(t *testing.T) {
	mgr := New(Options{DefaultDeadline: 200 * time.Millisecond})
	defer mgr.Close()

	pc := mgr.PacketConn()
	defer pc.Close()

	_ = pc.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	buf := make([]byte, 1024)
	start := time.Now()
	_, _, err := pc.ReadFrom(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("expected net.Error with Timeout() true, got %v", err)
	}
	if elapsed < 50*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("read returned at unexpected time: %v", elapsed)
	}
}

// TestPacketConn_CloseUnblocksReader ensures Close wakes a pending ReadFrom.
func TestPacketConn_CloseUnblocksReader(t *testing.T) {
	mgr := New(Options{DefaultDeadline: 200 * time.Millisecond})
	defer mgr.Close()

	pc := mgr.PacketConn()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, _, err := pc.ReadFrom(buf)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = pc.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected error from ReadFrom after Close")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("Close did not unblock pending ReadFrom")
	}
}

// TestPacketConn_DispatchesUniqueResponses puts two concurrent writers on
// the same PacketConn and verifies both responses arrive.
func TestPacketConn_DispatchesUniqueResponses(t *testing.T) {
	var n atomic.Int64
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg {
		n.Add(1)
		return reply(q, "192.0.2.210")
	})

	mgr := New(Options{DefaultDeadline: time.Second, DefaultResolverTimeout: 200 * time.Millisecond})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: up.Address()}); err != nil {
		t.Fatal(err)
	}

	pc := mgr.PacketConn()
	defer pc.Close()

	q1 := newQ("one.example.")
	q1.Id = 1111
	q2 := newQ("two.example.")
	q2.Id = 2222
	w1, _ := q1.Pack()
	w2, _ := q2.Pack()
	_, _ = pc.WriteTo(w1, nil)
	_, _ = pc.WriteTo(w2, nil)

	seen := map[uint16]bool{}
	deadline := time.Now().Add(2 * time.Second)
	for len(seen) < 2 && time.Now().Before(deadline) {
		_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 4096)
		nr, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:nr]); err == nil {
			seen[resp.Id] = true
		}
	}
	if !seen[1111] || !seen[2222] {
		t.Fatalf("missing responses, saw %#v", seen)
	}
}

// TestPacketConn_DoesNotCloseManager verifies the PacketConn doesn't take
// ownership of the Manager — Close on the conn must leave the Manager and
// the underlying upstreams alive.
func TestPacketConn_DoesNotCloseManager(t *testing.T) {
	up := startUDPUpstream(t, func(q *dns.Msg) *dns.Msg { return reply(q, "192.0.2.220") })
	mgr := New(Options{DefaultDeadline: time.Second, DefaultResolverTimeout: 200 * time.Millisecond})
	defer mgr.Close()
	if _, err := mgr.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: up.Address()}); err != nil {
		t.Fatal(err)
	}

	pc := mgr.PacketConn()
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}

	// Manager must still serve direct Resolve calls.
	resp, err := mgr.Resolve(context.Background(), newQ("after-close.example."))
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Manager unusable after PacketConn.Close: err=%v resp=%#v", err, resp)
	}
}
