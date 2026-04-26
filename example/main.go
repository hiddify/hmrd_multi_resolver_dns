// Command multidns-example runs the multidns library as a local DNS server.
//
// Usage:
//
//	multidns-example -listen :5353 \
//	    -upstream udp://1.1.1.1:53 \
//	    -upstream udp://8.8.8.8:53 \
//	    -upstream dot://1.1.1.1:853 \
//	    -upstream doh://https://cloudflare-dns.com/dns-query
//
// Test with: dig @127.0.0.1 -p 5353 google.com
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
)

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

type stdLogger struct{}

func (stdLogger) Debugf(f string, a ...any) { log.Printf("DEBUG "+f, a...) }
func (stdLogger) Infof(f string, a ...any)  { log.Printf("INFO  "+f, a...) }
func (stdLogger) Warnf(f string, a ...any)  { log.Printf("WARN  "+f, a...) }
func (stdLogger) Errorf(f string, a ...any) { log.Printf("ERROR "+f, a...) }

func main() {
	var (
		listen    = flag.String("listen", ":5353", "DNS listen address (UDP+TCP)")
		upstreams stringSlice
		deadline  = flag.Duration("deadline", 5*time.Second, "default per-query deadline")
		probe     = flag.Duration("probe", 5*time.Second, "down-resolver probe interval")
		statsEvery = flag.Duration("stats", 0, "if >0, log stats at this interval")
	)
	flag.Var(&upstreams, "upstream", "upstream resolver, e.g. udp://1.1.1.1:53 | tcp://1.1.1.1:53 | dot://1.1.1.1:853 | doh://https://cloudflare-dns.com/dns-query (repeat for multiple)")
	flag.Parse()

	if len(upstreams) == 0 {
		fmt.Fprintln(os.Stderr, "at least one -upstream is required")
		flag.Usage()
		os.Exit(2)
	}

	mgr := multidns.New(multidns.Options{
		DefaultDeadline: *deadline,
		ProbeInterval:   *probe,
		Logger:          stdLogger{},
	})
	defer mgr.Close()

	for _, raw := range upstreams {
		cfg, err := parseUpstream(raw)
		if err != nil {
			log.Fatalf("invalid -upstream %q: %v", raw, err)
		}
		id, err := mgr.AddResolver(cfg)
		if err != nil {
			log.Fatalf("add resolver %q: %v", raw, err)
		}
		log.Printf("added %s -> %s", id, raw)
	}

	srv := mgr.NewServer(*listen)
	go func() {
		log.Printf("listening on %s (udp+tcp)", *listen)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("server: %v", err)
		}
	}()

	if *statsEvery > 0 {
		go func() {
			t := time.NewTicker(*statsEvery)
			defer t.Stop()
			for range t.C {
				for _, s := range mgr.Stats() {
					log.Printf("stat %s state=%s valid=%d invalid=%d timeout=%d cap=%d ewma=%v",
						s.Name, s.State, s.ValidCount, s.InvalidCount, s.TimeoutCount,
						s.CurrentRPMCap, s.LatencyEWMA)
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func parseUpstream(raw string) (multidns.ResolverConfig, error) {
	// Accept either scheme://addr or scheme://https-url for doh.
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return multidns.ResolverConfig{}, fmt.Errorf("missing scheme")
	}
	scheme := strings.ToLower(raw[:idx])
	rest := raw[idx+3:]

	cfg := multidns.ResolverConfig{Address: rest, Name: raw}
	switch scheme {
	case "udp":
		cfg.Protocol = multidns.ProtoUDP
	case "tcp":
		cfg.Protocol = multidns.ProtoTCP
	case "dot":
		cfg.Protocol = multidns.ProtoDoT
	case "doh":
		cfg.Protocol = multidns.ProtoDoH
		// rest may already be a full https URL or just host:port/path; accept both.
		if !strings.HasPrefix(rest, "http://") && !strings.HasPrefix(rest, "https://") {
			cfg.Address = "https://" + rest
		}
		if _, err := url.Parse(cfg.Address); err != nil {
			return cfg, err
		}
	default:
		return cfg, fmt.Errorf("unknown scheme %q", scheme)
	}
	return cfg, nil
}
