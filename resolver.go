package multidns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// upstream is the internal interface every resolver transport implements.
type upstream interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
	Close() error
}

func newUpstream(cfg ResolverConfig) (upstream, error) {
	if cfg.Address == "" {
		return nil, errors.New("multidns: resolver address is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	switch cfg.Protocol {
	case ProtoUDP:
		return newDNSClientUpstream("udp", cfg, timeout, nil)
	case ProtoTCP:
		return newDNSClientUpstream("tcp", cfg, timeout, nil)
	case ProtoDoT:
		tlsCfg := cfg.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		host, _, err := net.SplitHostPort(cfg.Address)
		if err == nil && tlsCfg.ServerName == "" {
			c := tlsCfg.Clone()
			c.ServerName = host
			tlsCfg = c
		}
		return newDNSClientUpstream("tcp-tls", cfg, timeout, tlsCfg)
	case ProtoDoH:
		return newDoHUpstream(cfg, timeout)
	default:
		return nil, fmt.Errorf("multidns: unsupported protocol %q", cfg.Protocol)
	}
}

// dnsClientUpstream wraps a *dns.Client for UDP/TCP/DoT.
type dnsClientUpstream struct {
	client *dns.Client
	addr   string
	dialer DialFunc
}

func newDNSClientUpstream(net string, cfg ResolverConfig, timeout time.Duration, tlsCfg *tls.Config) (*dnsClientUpstream, error) {
	c := &dns.Client{
		Net:          net,
		Timeout:      timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		DialTimeout:  timeout,
		TLSConfig:    tlsCfg,
	}
	return &dnsClientUpstream{
		client: c,
		addr:   cfg.Address,
		dialer: cfg.Dialer,
	}, nil
}

func (u *dnsClientUpstream) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if u.dialer == nil {
		resp, _, err := u.client.ExchangeContext(ctx, q, u.addr)
		return resp, err
	}
	dialNet := "udp"
	switch u.client.Net {
	case "tcp", "tcp-tls":
		dialNet = "tcp"
	}
	rawConn, err := u.dialer(ctx, dialNet, u.addr)
	if err != nil {
		return nil, err
	}
	var c net.Conn = rawConn
	if u.client.Net == "tcp-tls" {
		host, _, _ := net.SplitHostPort(u.addr)
		tlsCfg := u.client.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{ServerName: host}
		} else if tlsCfg.ServerName == "" {
			cloned := tlsCfg.Clone()
			cloned.ServerName = host
			tlsCfg = cloned
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		c = tlsConn
	}
	dconn := &dns.Conn{Conn: c}
	defer dconn.Close()
	// Honor the query's EDNS0 UDP buffer size when the caller advertised
	// one; otherwise dns.Conn.ReadMsg caps UDP reads at MinMsgSize (512),
	// which would silently truncate large responses on the custom-dialer
	// path. The non-custom path goes through dns.Client which does this
	// for us.
	if u.client.Net == "udp" {
		if opt := q.IsEdns0(); opt != nil {
			if size := opt.UDPSize(); size >= dns.MinMsgSize {
				dconn.UDPSize = size
			}
		}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else if u.client.Timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(u.client.Timeout))
	}
	if err := dconn.WriteMsg(q); err != nil {
		return nil, err
	}
	return dconn.ReadMsg()
}

func (u *dnsClientUpstream) Close() error { return nil }

// dohUpstream is an RFC 8484 DNS-over-HTTPS client.
type dohUpstream struct {
	endpoint *url.URL
	client   *http.Client
}

func newDoHUpstream(cfg ResolverConfig, timeout time.Duration) (*dohUpstream, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("multidns: parse DoH endpoint: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("multidns: DoH endpoint must be http(s), got %q", u.Scheme)
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     cfg.TLSConfig,
	}
	if cfg.Dialer != nil {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cfg.Dialer(ctx, network, addr)
		}
	}
	return &dohUpstream{
		endpoint: u,
		client:   &http.Client{Transport: tr, Timeout: timeout},
	}, nil
}

func (u *dohUpstream) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("doh: rate limited (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("doh: server error (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("doh: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: unpack response: %w", err)
	}
	return out, nil
}

func (u *dohUpstream) Close() error {
	if t, ok := u.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}
