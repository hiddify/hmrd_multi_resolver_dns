package multidns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server is an optional UDP/TCP DNS listener that exposes a Manager on a
// network address. Both transports listen by default; pass explicit network
// names to NewServer to limit the surface (e.g. "udp" only).
type Server struct {
	mgr      *Manager
	addr     string
	networks []string

	mu      sync.Mutex
	servers []*dns.Server
}

// NewServer creates a server bound to addr. If networks is empty, both UDP
// and TCP are served.
func (m *Manager) NewServer(addr string, networks ...string) *Server {
	if len(networks) == 0 {
		networks = []string{"udp", "tcp"}
	}
	return &Server{mgr: m, addr: addr, networks: networks}
}

// ListenAndServe blocks until the listeners exit (typically after Shutdown).
// It returns the first non-nil error from the underlying listeners.
func (s *Server) ListenAndServe() error {
	handler := dns.HandlerFunc(s.handle)

	s.mu.Lock()
	for _, n := range s.networks {
		srv := &dns.Server{
			Addr:    s.addr,
			Net:     n,
			Handler: handler,
		}
		s.servers = append(s.servers, srv)
	}
	servers := append([]*dns.Server{}, s.servers...)
	s.mu.Unlock()

	errCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	for _, srv := range servers {
		srv := srv
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.ListenAndServe(); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Shutdown stops the listeners. Subsequent calls are no-ops.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	servers := append([]*dns.Server{}, s.servers...)
	s.servers = nil
	s.mu.Unlock()

	var firstErr error
	for _, srv := range servers {
		if err := srv.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) handle(w dns.ResponseWriter, q *dns.Msg) {
	deadline := s.mgr.opts.DefaultDeadline
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	resp, err := s.mgr.Resolve(ctx, q)
	if err != nil || resp == nil {
		s.mgr.opts.Logger.Warnf("multidns: server resolve failed: %v", err)
		fail := errResponse(q, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}
	resp.Id = q.Id
	if err := w.WriteMsg(resp); err != nil {
		s.mgr.opts.Logger.Warnf("multidns: server write failed: %v", err)
	}
}

func errResponse(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	return r
}
