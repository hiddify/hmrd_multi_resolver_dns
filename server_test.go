package multidns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServerEndToEnd(t *testing.T) {
	m := New(Options{DefaultDeadline: 500 * time.Millisecond})
	defer m.Close()

	mu := &mockUpstream{}
	mu.setRespond(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeSuccess
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(192, 0, 2, 1),
		})
		return r, nil
	})
	addMock(t, m, "mock", mu)

	// Bind to an ephemeral UDP port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close() // release; the server will re-bind

	srv := m.NewServer(addr, "udp")
	go func() { _ = srv.ListenAndServe() }()

	// Wait for the server to be ready.
	deadline := time.Now().Add(500 * time.Millisecond)
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 200 * time.Millisecond

	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)

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
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got %#v", resp)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
