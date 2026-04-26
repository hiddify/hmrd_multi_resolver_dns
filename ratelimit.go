package multidns

import (
	"sync"
	"time"
)

// slidingCounter counts events over a 60-second window using one bucket per
// second. It is safe for concurrent use.
type slidingCounter struct {
	mu      sync.Mutex
	buckets [60]int64
	last    int64 // unix second of the most recent bucket update
}

func (s *slidingCounter) add(now time.Time, n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(now.Unix())
	s.buckets[now.Unix()%60] += n
}

func (s *slidingCounter) sum(now time.Time) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(now.Unix())
	var total int64
	for _, v := range s.buckets {
		total += v
	}
	return total
}

func (s *slidingCounter) advance(nowSec int64) {
	if s.last == 0 {
		s.last = nowSec
		return
	}
	gap := nowSec - s.last
	if gap <= 0 {
		return
	}
	if gap >= 60 {
		s.buckets = [60]int64{}
	} else {
		for i := int64(1); i <= gap; i++ {
			s.buckets[(s.last+i)%60] = 0
		}
	}
	s.last = nowSec
}

// tokenBucket enforces an RPM cap. capPerMin == 0 means no cap (always
// permits). Permits are refilled continuously at capPerMin/60 per second up
// to a burst of capPerMin/4 (clamped between 1 and capPerMin).
type tokenBucket struct {
	mu         sync.Mutex
	capPerMin  int
	tokens     float64
	burst      float64
	lastRefill time.Time
}

func newTokenBucket(capPerMin int) *tokenBucket {
	tb := &tokenBucket{}
	tb.setCap(capPerMin)
	return tb
}

func (tb *tokenBucket) setCap(capPerMin int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.capPerMin = capPerMin
	if capPerMin <= 0 {
		tb.tokens = 0
		tb.burst = 0
		return
	}
	burst := float64(capPerMin) / 4
	if burst < 1 {
		burst = 1
	}
	if burst > float64(capPerMin) {
		burst = float64(capPerMin)
	}
	tb.burst = burst
	if tb.tokens > burst {
		tb.tokens = burst
	}
	if tb.tokens <= 0 {
		tb.tokens = burst
	}
}

func (tb *tokenBucket) cap() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.capPerMin
}

// tryAcquire returns true if a permit was available. When capPerMin == 0 it
// always returns true (no cap).
func (tb *tokenBucket) tryAcquire(now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.capPerMin <= 0 {
		return true
	}
	tb.refillLocked(now)
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

func (tb *tokenBucket) refillLocked(now time.Time) {
	if tb.lastRefill.IsZero() {
		tb.lastRefill = now
		return
	}
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	tb.tokens += elapsed * (float64(tb.capPerMin) / 60)
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}
	tb.lastRefill = now
}
