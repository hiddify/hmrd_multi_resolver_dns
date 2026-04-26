package multidns

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ErrAllResolversFailed is returned when every candidate resolver was tried
// (or skipped) without producing a usable response inside the deadline.
var ErrAllResolversFailed = errors.New("multidns: all resolvers failed")

// ErrNoResolvers is returned when Resolve is called but no resolvers are
// registered.
var ErrNoResolvers = errors.New("multidns: no resolvers registered")

// errThrottled is an internal sentinel signalling the bucket rejected the
// attempt; the pool uses it to decide whether to fall back to forcing a
// throttled candidate.
var errThrottled = errors.New("multidns: throttled")

type pool struct {
	mu        sync.RWMutex
	resolvers []*resolverState
	rrIndex   atomic.Uint64
	opts      *Options
}

func newPool(opts *Options) *pool {
	return &pool{opts: opts}
}

func (p *pool) add(rs *resolverState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	updated := make([]*resolverState, 0, len(p.resolvers)+1)
	updated = append(updated, p.resolvers...)
	updated = append(updated, rs)
	p.resolvers = updated
}

func (p *pool) remove(id string) (*resolverState, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, r := range p.resolvers {
		if r.id == id {
			updated := make([]*resolverState, 0, len(p.resolvers)-1)
			updated = append(updated, p.resolvers[:i]...)
			updated = append(updated, p.resolvers[i+1:]...)
			p.resolvers = updated
			return r, true
		}
	}
	return nil, false
}

func (p *pool) snapshot() []*resolverState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*resolverState, len(p.resolvers))
	copy(out, p.resolvers)
	return out
}

// candidates orders resolvers for one query: healthy first, then rate_limited,
// skipping anything currently down. Within healthy/rate_limited the order
// depends on LBStrategy.
func (p *pool) candidates() []*resolverState {
	resolvers := p.snapshot()
	if len(resolvers) == 0 {
		return nil
	}

	var healthy, limited []*resolverState
	for _, r := range resolvers {
		switch r.currentState() {
		case stateHealthy:
			healthy = append(healthy, r)
		case stateRateLimited:
			limited = append(limited, r)
		}
	}

	switch p.opts.LoadBalance {
	case LBLowestLatency:
		sortByLatency(healthy)
		sortByLatency(limited)
	case LBWeighted:
		// Weighted is approximated by sorting by weight desc then rotating.
		sortByWeightDesc(healthy)
		sortByWeightDesc(limited)
		rotate(healthy, int(p.rrIndex.Add(1)))
	default: // round-robin
		rotate(healthy, int(p.rrIndex.Add(1)))
	}

	out := make([]*resolverState, 0, len(healthy)+len(limited))
	out = append(out, healthy...)
	out = append(out, limited...)
	return out
}

func sortByLatency(rs []*resolverState) {
	sort.SliceStable(rs, func(i, j int) bool {
		li, lj := rs[i].latencyEWMA(), rs[j].latencyEWMA()
		if li == 0 {
			return false
		}
		if lj == 0 {
			return true
		}
		return li < lj
	})
}

func sortByWeightDesc(rs []*resolverState) {
	sort.SliceStable(rs, func(i, j int) bool {
		return rs[i].cfg.Weight > rs[j].cfg.Weight
	})
}

func rotate(rs []*resolverState, by int) {
	if len(rs) <= 1 {
		return
	}
	by = by % len(rs)
	if by < 0 {
		by += len(rs)
	}
	tmp := make([]*resolverState, len(rs))
	copy(tmp, rs)
	copy(rs, tmp[by:])
	copy(rs[len(rs)-by:], tmp[:by])
}

// resolve runs the deadline-aware retry across candidates.
func (p *pool) resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	candidates := p.candidates()
	if len(candidates) == 0 {
		// If everything is down, still fall back to the full set so a probe
		// path or a transient classification doesn't strand the caller.
		all := p.snapshot()
		if len(all) == 0 {
			return nil, ErrNoResolvers
		}
		candidates = all
	}

	var lastErr error
	everSent := false
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		now := time.Now()
		if !c.bucket.tryAcquire(now) {
			lastErr = errThrottled
			continue
		}
		resp, err, ok := p.attempt(ctx, c, q)
		if ok {
			return resp, nil
		}
		everSent = true
		if err != nil {
			lastErr = err
		}
	}

	// If every candidate was throttled, force one through (ignore the bucket)
	// so callers aren't stranded by aggressive AIMD.
	if !everSent && len(candidates) > 0 && ctx.Err() == nil {
		for _, c := range candidates {
			if ctx.Err() != nil {
				break
			}
			resp, err, ok := p.attempt(ctx, c, q)
			if ok {
				return resp, nil
			}
			if err != nil {
				lastErr = err
			}
		}
	}

	if lastErr == nil {
		lastErr = ErrAllResolversFailed
	}
	return nil, errors.Join(ErrAllResolversFailed, lastErr)
}

func (p *pool) attempt(ctx context.Context, c *resolverState, q *dns.Msg) (*dns.Msg, error, bool) {
	attemptCtx, cancel := capContext(ctx, c.cfg.Timeout)
	start := time.Now()
	resp, err := c.up.Exchange(attemptCtx, q)
	cancel()
	latency := time.Since(start)
	kind := classify(resp, err)
	c.record(time.Now(), kind, latency, q)
	if kind == failNone {
		return resp, nil, true
	}
	if err == nil && resp != nil {
		err = errFromRcode(resp.Rcode)
	}
	return nil, err, false
}

// capContext returns a context whose deadline is the earlier of the parent's
// deadline and now+cap. cap <= 0 means no per-attempt cap.
func capContext(parent context.Context, perAttempt time.Duration) (context.Context, context.CancelFunc) {
	if perAttempt <= 0 {
		return context.WithCancel(parent)
	}
	deadline := time.Now().Add(perAttempt)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return context.WithDeadline(parent, deadline)
}

func errFromRcode(rcode int) error {
	return &rcodeErr{rcode: rcode}
}

type rcodeErr struct{ rcode int }

func (e *rcodeErr) Error() string { return "multidns: upstream rcode " + dns.RcodeToString[e.rcode] }
