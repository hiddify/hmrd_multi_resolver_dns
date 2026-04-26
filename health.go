package multidns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type healthState int32

const (
	stateHealthy healthState = iota
	stateRateLimited
	stateDown
)

func (h healthState) String() string {
	switch h {
	case stateHealthy:
		return "healthy"
	case stateRateLimited:
		return "rate_limited"
	case stateDown:
		return "down"
	default:
		return "unknown"
	}
}

type failKind int

const (
	failNone failKind = iota
	failTimeout
	failNetwork
	failRateLimit
	failBadResponse
	failOther
)

// classify maps an Exchange result to a failKind. A non-nil response is
// inspected for Rcode regardless of err being nil so DoH/SERVFAIL paths land
// in the right bucket.
func classify(resp *dns.Msg, err error) failKind {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return failTimeout
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return failTimeout
		}
		// HTTP 429 from the DoH transport surfaces as a wrapped error; we
		// flag it via a sentinel string rather than a typed error to avoid
		// leaking the internal type.
		if strings.Contains(err.Error(), "doh: rate limited") {
			return failRateLimit
		}
		if strings.Contains(err.Error(), "doh: server error") {
			return failRateLimit
		}
		return failNetwork
	}
	if resp == nil {
		return failBadResponse
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return failNone
	case dns.RcodeRefused, dns.RcodeServerFailure:
		return failRateLimit
	case dns.RcodeFormatError, dns.RcodeNotImplemented:
		return failBadResponse
	default:
		return failOther
	}
}

// resolverState carries everything we know about a single upstream and its
// runtime health.
type resolverState struct {
	id   string
	cfg  ResolverConfig
	up   upstream
	opts *Options

	state atomic.Int32

	validCount       atomic.Int64
	invalidCount     atomic.Int64
	timeoutCount     atomic.Int64
	rateLimitedCount atomic.Int64

	consecutiveFails atomic.Int64

	recentReqs slidingCounter
	recentRL   slidingCounter

	bucket *tokenBucket

	// latencyEWMANanos is the EWMA of successful Exchange latencies, in
	// nanoseconds. Stored atomically so candidate selection (sort) can read
	// it without holding mu.
	latencyEWMANanos atomic.Int64

	mu           sync.Mutex
	failingQuery *dns.Msg
	lastValid    time.Time
	lastFail     time.Time

	// rrAdditiveAt is the next wall-clock at which we add a token to the cap
	// when no rate-limit failures have been seen.
	rrAdditiveAt time.Time

	probeCancel context.CancelFunc
}

func newResolverState(id string, cfg ResolverConfig, up upstream, opts *Options) *resolverState {
	rs := &resolverState{
		id:     id,
		cfg:    cfg,
		up:     up,
		opts:   opts,
		bucket: newTokenBucket(cfg.InitialRPM),
	}
	rs.state.Store(int32(stateHealthy))
	return rs
}

func (rs *resolverState) currentState() healthState {
	return healthState(rs.state.Load())
}

func (rs *resolverState) setState(s healthState) {
	rs.state.Store(int32(s))
}

// record updates counters, sliding windows, and state transitions for one
// completed (or failed) Exchange attempt.
func (rs *resolverState) record(now time.Time, kind failKind, latency time.Duration, q *dns.Msg) {
	rs.recentReqs.add(now, 1)

	switch kind {
	case failNone:
		rs.validCount.Add(1)
		rs.consecutiveFails.Store(0)
		rs.updateLatencyEWMA(latency)
		rs.mu.Lock()
		rs.lastValid = now
		rs.failingQuery = nil
		rs.mu.Unlock()
		rs.maybeAdditiveIncrease(now)
		if rs.currentState() != stateHealthy && rs.bucket.cap() == 0 {
			rs.setState(stateHealthy)
		}

	case failBadResponse:
		// Don't penalise the resolver — likely client-side issue.
		return

	case failTimeout:
		rs.timeoutCount.Add(1)
		rs.invalidCount.Add(1)
		rs.consecutiveFails.Add(1)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
		rs.maybeMarkDown(q)

	case failNetwork:
		rs.invalidCount.Add(1)
		rs.consecutiveFails.Add(1)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
		rs.maybeMarkDown(q)

	case failRateLimit:
		rs.invalidCount.Add(1)
		rs.rateLimitedCount.Add(1)
		rs.recentRL.add(now, 1)
		rs.consecutiveFails.Store(0)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
		rs.applyRateLimitDecrease(now)

	default:
		rs.invalidCount.Add(1)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
	}
}

func (rs *resolverState) maybeMarkDown(q *dns.Msg) {
	threshold := int64(rs.opts.DownAfterFailures)
	if threshold <= 0 {
		threshold = 8
	}
	if rs.consecutiveFails.Load() < threshold {
		return
	}
	if rs.currentState() == stateDown {
		return
	}
	rs.mu.Lock()
	if q != nil {
		rs.failingQuery = q.Copy()
	}
	rs.mu.Unlock()
	rs.setState(stateDown)
}

func (rs *resolverState) applyRateLimitDecrease(now time.Time) {
	cap := rs.bucket.cap()
	if cap == 0 {
		recent := int(rs.recentReqs.sum(now))
		if recent <= 0 {
			recent = rs.opts.RateLimitFloorRPM * 4
		}
		newCap := recent / 2
		if newCap < rs.opts.RateLimitFloorRPM {
			newCap = rs.opts.RateLimitFloorRPM
		}
		rs.bucket.setCap(newCap)
	} else {
		newCap := cap / 2
		if newCap < rs.opts.RateLimitFloorRPM {
			newCap = rs.opts.RateLimitFloorRPM
		}
		rs.bucket.setCap(newCap)
	}
	rs.setState(stateRateLimited)
	rs.mu.Lock()
	rs.rrAdditiveAt = now.Add(time.Minute)
	rs.mu.Unlock()
}

func (rs *resolverState) maybeAdditiveIncrease(now time.Time) {
	cap := rs.bucket.cap()
	if cap == 0 {
		return
	}
	rs.mu.Lock()
	due := !rs.rrAdditiveAt.IsZero() && now.After(rs.rrAdditiveAt)
	if due {
		rs.rrAdditiveAt = now.Add(time.Minute)
	}
	rs.mu.Unlock()
	if !due {
		return
	}
	if rs.recentRL.sum(now) > 0 {
		return
	}
	newCap := cap + rs.opts.RateLimitAdditive
	if newCap >= rs.opts.RateLimitUncapRPM {
		rs.bucket.setCap(0)
		rs.setState(stateHealthy)
		return
	}
	rs.bucket.setCap(newCap)
}

func (rs *resolverState) updateLatencyEWMA(latency time.Duration) {
	cur := rs.latencyEWMANanos.Load()
	var next int64
	if cur == 0 {
		next = int64(latency)
	} else {
		next = (cur*7 + int64(latency)) / 8
	}
	rs.latencyEWMANanos.Store(next)
}

func (rs *resolverState) latencyEWMA() time.Duration {
	return time.Duration(rs.latencyEWMANanos.Load())
}

func (rs *resolverState) snapshot() ResolverStat {
	rs.mu.Lock()
	lastValid := rs.lastValid
	lastFail := rs.lastFail
	rs.mu.Unlock()
	return ResolverStat{
		ID:            rs.id,
		Name:          rs.cfg.Name,
		State:         rs.currentState().String(),
		ValidCount:    rs.validCount.Load(),
		InvalidCount:  rs.invalidCount.Load(),
		TimeoutCount:  rs.timeoutCount.Load(),
		RateLimited:   rs.rateLimitedCount.Load(),
		CurrentRPMCap: rs.bucket.cap(),
		RecentRPM:     int(rs.recentReqs.sum(time.Now())),
		LatencyEWMA:   rs.latencyEWMA(),
		LastValid:     lastValid,
		LastFail:      lastFail,
	}
}

func (rs *resolverState) info() ResolverInfo {
	return ResolverInfo{
		ID:       rs.id,
		Name:     rs.cfg.Name,
		Protocol: rs.cfg.Protocol,
		Address:  rs.cfg.Address,
		Weight:   rs.cfg.Weight,
	}
}
