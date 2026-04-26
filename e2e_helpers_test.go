package multidns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// upstreamHandler is the programmable behavior of a real test upstream.
// It receives the full query and returns either a response (which is sent
// verbatim) or returns nil to drop the query (no response — provokes a
// timeout on the client).
type upstreamHandler func(q *dns.Msg) *dns.Msg

// realUpstream is one in-process DNS upstream we spin up for e2e tests.
type realUpstream struct {
	t        *testing.T
	addr     string
	udp      *dns.Server
	tcp      *dns.Server
	doh      *http.Server
	dot      *dns.Server
	tlsCert  tls.Certificate
	tlsCAPEM []byte

	calls atomic.Int64

	// handler is replaceable while running so tests can flip behavior mid-flight.
	handler atomic.Pointer[upstreamHandler]
}

func (u *realUpstream) setHandler(h upstreamHandler) {
	hh := h
	u.handler.Store(&hh)
}

func (u *realUpstream) callsCount() int64 { return u.calls.Load() }

func (u *realUpstream) handle(w dns.ResponseWriter, q *dns.Msg) {
	u.calls.Add(1)
	hp := u.handler.Load()
	if hp == nil {
		return
	}
	resp := (*hp)(q)
	if resp == nil {
		return // drop, force client timeout
	}
	resp.Id = q.Id
	_ = w.WriteMsg(resp)
}

// startUDPUpstream spins up a real miekg/dns UDP server on a free port.
func startUDPUpstream(t *testing.T, h upstreamHandler) *realUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	u := &realUpstream{t: t, addr: pc.LocalAddr().String()}
	u.setHandler(h)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(u.handle)}
	u.udp = srv
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return u
}

// startTCPUpstream spins up a real miekg/dns TCP server.
func startTCPUpstream(t *testing.T, h upstreamHandler) *realUpstream {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	u := &realUpstream{t: t, addr: l.Addr().String()}
	u.setHandler(h)
	srv := &dns.Server{Listener: l, Net: "tcp", Handler: dns.HandlerFunc(u.handle)}
	u.tcp = srv
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return u
}

// startDoTUpstream spins up a TLS-wrapped DNS server (DoT) with a self-signed cert.
func startDoTUpstream(t *testing.T, h upstreamHandler) *realUpstream {
	t.Helper()
	cert, caPEM := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	u := &realUpstream{t: t, addr: l.Addr().String(), tlsCert: cert, tlsCAPEM: caPEM}
	u.setHandler(h)
	srv := &dns.Server{Listener: l, Net: "tcp-tls", Handler: dns.HandlerFunc(u.handle), TLSConfig: tlsCfg}
	u.dot = srv
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return u
}

// startDoHUpstream spins up an HTTPS server that accepts RFC 8484 DoH POSTs.
func startDoHUpstream(t *testing.T, h upstreamHandler) *realUpstream {
	t.Helper()
	cert, caPEM := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen tls (doh): %v", err)
	}
	u := &realUpstream{t: t, addr: l.Addr().String(), tlsCert: cert, tlsCAPEM: caPEM}
	u.setHandler(h)

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		hp := u.handler.Load()
		if hp == nil {
			http.Error(w, "no handler", http.StatusInternalServerError)
			return
		}
		resp := (*hp)(q)
		// Sentinel to allow tests to provoke HTTP-level rate-limit / 5xx.
		if resp == nil {
			// no-response handler: hang briefly then close to provoke timeout
			time.Sleep(50 * time.Millisecond)
			return
		}
		// Special opcode: a NOTIMPL response with a zero-length question is
		// reinterpreted as "send 429".
		if resp.Rcode == dns.RcodeRefused && len(resp.Question) == 0 {
			http.Error(w, "rate", http.StatusTooManyRequests)
			return
		}
		if resp.Rcode == dns.RcodeServerFailure && len(resp.Question) == 0 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack", 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	u.doh = srv
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return u
}

// dohURL returns the https://host:port/dns-query endpoint string.
func (u *realUpstream) dohURL() string {
	return "https://" + u.addr + "/dns-query"
}

// clientTLSConfig returns a tls.Config that trusts this upstream's cert,
// suitable to plug into ResolverConfig.TLSConfig for DoT/DoH.
func (u *realUpstream) clientTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(u.tlsCAPEM)
	return &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}
}

func generateSelfSignedCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "multidns-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost", "127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert, certPEM
}

// reply builds a successful A response for q with the given IP.
func reply(q *dns.Msg, ip string) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = dns.RcodeSuccess
	if len(q.Question) > 0 {
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: net.ParseIP(ip).To4(),
		})
	}
	return r
}

// rcodeOnly builds a response with only an Rcode (used by tests for REFUSED/SERVFAIL).
func rcodeOnly(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = rcode
	return r
}

// dohRateLimitSentinel returns a response interpreted by the DoH test handler
// as "respond with HTTP 429" (so the upstream surfaces a transport-level
// rate-limit signal rather than a DNS-level one).
func dohRateLimitSentinel() *dns.Msg {
	r := new(dns.Msg)
	r.Rcode = dns.RcodeRefused
	r.Question = nil
	return r
}

// newQ builds a query for "name. A".
func newQ(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.RecursionDesired = true
	return q
}

// addressOnly returns just "host:port" from any e2e upstream.
func (u *realUpstream) Address() string { return u.addr }

// hint to keep the compiler happy when fmt is unused in some build.
var _ = fmt.Sprintf
