package multidns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startUDPUpstreamForTest spins up a tiny in-process miekg/dns UDP server
// that answers any A query with `ip`, simulating a recursive resolver.
func startUDPUpstreamForTest(t *testing.T, ip string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			r := new(dns.Msg)
			r.SetReply(q)
			r.Rcode = dns.RcodeSuccess
			if len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeA {
				r.Answer = append(r.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP(ip).To4(),
				})
			}
			_ = w.WriteMsg(r)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// TestStartLocalEndToEnd builds a Manager via StartLocal, registers a single
// upstream via the URL helper, sends a query at the local listener, and
// confirms the answer routed through the pool.
func TestStartLocalEndToEnd(t *testing.T) {
	upstream, stop := startUDPUpstreamForTest(t, "192.0.2.10")
	defer stop()

	mgr, addr, err := StartLocal(Options{DefaultDeadline: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("StartLocal: %v", err)
	}
	defer mgr.Close()

	if _, err := mgr.AddResolverURL("udp://" + upstream); err != nil {
		t.Fatalf("AddResolverURL: %v", err)
	}

	c := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion("answer.test.", dns.TypeA)

	// Tight retry loop while the listener finishes wiring up.
	deadline := time.Now().Add(time.Second)
	var resp *dns.Msg
	for time.Now().Before(deadline) {
		resp, _, err = c.Exchange(q, addr)
		if err == nil && resp != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("unexpected resp: %#v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("answer mismatch: %#v", resp.Answer[0])
	}
}

// TestStartLocalCloseStopsListener verifies Manager.Close also tears down
// the bundled local listener (subsequent UDP queries should error out).
func TestStartLocalCloseStopsListener(t *testing.T) {
	mgr, addr, err := StartLocal(Options{DefaultDeadline: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("StartLocal: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close, the kernel releases the port; sending a UDP query
	// triggers ICMP unreachable on most platforms but at minimum we should
	// see the timeout fire (no listener is answering).
	c := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion("noreply.test.", dns.TypeA)
	_, _, err = c.Exchange(q, addr)
	if err == nil {
		t.Fatalf("expected error after Close, got nil")
	}
}

// TestAddResolverURLDispatch ensures Resolve actually routes through a
// resolver added via AddResolverURL (covers the parse + dispatch path).
func TestAddResolverURLDispatch(t *testing.T) {
	upstream, stop := startUDPUpstreamForTest(t, "192.0.2.20")
	defer stop()

	mgr := New(Options{DefaultDeadline: 500 * time.Millisecond})
	defer mgr.Close()

	if _, err := mgr.AddResolverURL(upstream); err != nil {
		t.Fatalf("AddResolverURL: %v", err)
	}

	q := new(dns.Msg)
	q.SetQuestion("dispatch.test.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := mgr.Resolve(ctx, q)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("unexpected resp: %#v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("192.0.2.20")) {
		t.Fatalf("answer mismatch: %#v", resp.Answer[0])
	}
}
