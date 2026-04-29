package multidns

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseResolverURL turns a resolver address string into a ResolverConfig.
// Supported forms:
//
//	udp://1.1.1.1:53                       — explicit UDP
//	tcp://1.1.1.1:53                       — explicit TCP
//	dot://1.1.1.1:853                      — DNS-over-TLS
//	https://cloudflare-dns.com/dns-query   — DNS-over-HTTPS (full URL kept as Address)
//	1.1.1.1:53                             — bare host:port, defaults to UDP
//
// The point of accepting a single string is to give every embedder
// (sing-box's dnstt outbound, the smart-dns-pool service, anyone else)
// the same resolver-config grammar without each one re-implementing
// scheme parsing.
func ParseResolverURL(s string) (ResolverConfig, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ResolverConfig{}, fmt.Errorf("multidns: empty resolver address")
	}

	// No scheme → treat as UDP host:port (or host, default port 53).
	if !strings.Contains(s, "://") {
		return ResolverConfig{Protocol: ProtoUDP, Address: ensurePort(s, "53")}, nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return ResolverConfig{}, fmt.Errorf("multidns: parse %q: %w", s, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "udp":
		return ResolverConfig{Protocol: ProtoUDP, Address: ensurePort(u.Host, "53")}, nil
	case "tcp":
		return ResolverConfig{Protocol: ProtoTCP, Address: ensurePort(u.Host, "53")}, nil
	case "dot", "tls":
		return ResolverConfig{Protocol: ProtoDoT, Address: ensurePort(u.Host, "853")}, nil
	case "https", "doh":
		// DoH transports keep the full URL — Path matters for the
		// endpoint, not just the host. Normalize "doh://" to "https://"
		// so the http.Client sees a real scheme.
		if strings.EqualFold(u.Scheme, "doh") {
			u.Scheme = "https"
		}
		return ResolverConfig{Protocol: ProtoDoH, Address: u.String()}, nil
	default:
		return ResolverConfig{}, fmt.Errorf("multidns: unsupported scheme %q in %q", u.Scheme, s)
	}
}

// AddResolverURL is a convenience wrapper around ParseResolverURL +
// AddResolver. The returned id can later be passed to RemoveResolver.
func (m *Manager) AddResolverURL(s string) (string, error) {
	cfg, err := ParseResolverURL(s)
	if err != nil {
		return "", err
	}
	return m.AddResolver(cfg)
}

// ensurePort appends ":<defaultPort>" if host has no port. Leaves IPv6
// "[::1]:53"-style addresses alone, since net.SplitHostPort already accepts
// them.
func ensurePort(host, defaultPort string) string {
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}
