package multidns

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// startProbe runs a goroutine that periodically inspects the resolver and,
// while it is in the down state, re-issues the offending query (or a synthetic
// one) every ProbeInterval. On a valid response the resolver is returned to
// the healthy state and counters are reset.
func (m *Manager) startProbe(rs *resolverState) {
	ctx, cancel := context.WithCancel(m.probeCtx)
	rs.mu.Lock()
	rs.probeCancel = cancel
	rs.mu.Unlock()

	m.probeWG.Add(1)
	go func() {
		defer m.probeWG.Done()
		ticker := time.NewTicker(m.opts.ProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if rs.currentState() != stateDown {
					continue
				}
				m.probeOnce(ctx, rs)
			}
		}
	}()
}

func (m *Manager) probeOnce(ctx context.Context, rs *resolverState) {
	rs.mu.Lock()
	q := rs.failingQuery
	rs.mu.Unlock()
	if q == nil {
		q = defaultProbeQuery()
	} else {
		q = q.Copy()
		q.Id = dns.Id()
	}

	attemptCtx, cancel := capContext(ctx, rs.cfg.Timeout)
	defer cancel()
	start := time.Now()
	resp, err := rs.up.Exchange(attemptCtx, q)
	latency := time.Since(start)
	kind := classify(resp, err)
	if kind == failNone {
		rs.consecutiveFails.Store(0)
		rs.bucket.setCap(0)
		rs.setState(stateHealthy)
		rs.updateLatencyEWMA(latency)
		rs.mu.Lock()
		rs.lastValid = time.Now()
		rs.failingQuery = nil
		rs.mu.Unlock()
		m.opts.Logger.Infof("multidns: resolver %s recovered", rs.id)
		return
	}
	m.opts.Logger.Debugf("multidns: probe %s still failing (%v)", rs.id, err)
}

func defaultProbeQuery() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("dns.google.", dns.TypeA)
	q.RecursionDesired = true
	return q
}
