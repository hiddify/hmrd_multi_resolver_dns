package multidns

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Protocol identifies the wire transport used to talk to an upstream resolver.
type Protocol string

const (
	ProtoUDP Protocol = "udp"
	ProtoTCP Protocol = "tcp"
	ProtoDoT Protocol = "dot"
	ProtoDoH Protocol = "doh"
)

// LBStrategy controls candidate ordering when multiple resolvers are healthy.
type LBStrategy int

const (
	LBRoundRobin LBStrategy = iota
	LBWeighted
	LBLowestLatency
)

// DialFunc is the optional custom dialer hook. When set on a ResolverConfig
// it is used for UDP/TCP/DoT connections and as the http.Transport DialContext
// for DoH, so an embedder (e.g. hiddify-sing-box) can route DNS through a tunnel.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ResolverConfig describes a single upstream resolver.
type ResolverConfig struct {
	Name       string
	Protocol   Protocol
	Address    string
	Timeout    time.Duration
	TLSConfig  *tls.Config
	Dialer     DialFunc
	Weight     int
	InitialRPM int
}

// Options configures a Manager.
type Options struct {
	DefaultDeadline    time.Duration
	LoadBalance        LBStrategy
	ProbeInterval      time.Duration
	DownAfterFailures  int
	RateLimitFloorRPM  int
	RateLimitUncapRPM  int
	RateLimitAdditive  int
	// DefaultResolverTimeout is the per-attempt cap applied to a resolver
	// when its ResolverConfig.Timeout is unset. Defaults to 2s. This exists
	// so a single hung upstream cannot consume the entire DefaultDeadline
	// before failover kicks in.
	DefaultResolverTimeout time.Duration
	Logger                 Logger
}

// Logger is the minimal logging surface; defaults to a no-op. Embedders
// (e.g. sing-box) inject their own.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

func (o *Options) applyDefaults() {
	if o.DefaultDeadline <= 0 {
		o.DefaultDeadline = 5 * time.Second
	}
	if o.ProbeInterval <= 0 {
		o.ProbeInterval = 5 * time.Second
	}
	if o.DownAfterFailures <= 0 {
		o.DownAfterFailures = 8
	}
	if o.RateLimitFloorRPM <= 0 {
		o.RateLimitFloorRPM = 6
	}
	if o.RateLimitUncapRPM <= 0 {
		o.RateLimitUncapRPM = 600
	}
	if o.RateLimitAdditive <= 0 {
		o.RateLimitAdditive = 5
	}
	if o.DefaultResolverTimeout <= 0 {
		o.DefaultResolverTimeout = 2 * time.Second
	}
	if o.Logger == nil {
		o.Logger = nopLogger{}
	}
}
