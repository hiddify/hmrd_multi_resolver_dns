package multidns

import "testing"

func TestParseResolverURL(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantProto   Protocol
		wantAddr    string
		wantErr     bool
	}{
		{name: "udp explicit", in: "udp://1.1.1.1:53", wantProto: ProtoUDP, wantAddr: "1.1.1.1:53"},
		{name: "udp default port", in: "udp://1.1.1.1", wantProto: ProtoUDP, wantAddr: "1.1.1.1:53"},
		{name: "bare host port", in: "1.1.1.1:53", wantProto: ProtoUDP, wantAddr: "1.1.1.1:53"},
		{name: "bare host no port", in: "1.1.1.1", wantProto: ProtoUDP, wantAddr: "1.1.1.1:53"},
		{name: "tcp explicit", in: "tcp://1.1.1.1:53", wantProto: ProtoTCP, wantAddr: "1.1.1.1:53"},
		{name: "dot scheme", in: "dot://1.1.1.1:853", wantProto: ProtoDoT, wantAddr: "1.1.1.1:853"},
		{name: "dot default port", in: "dot://1.1.1.1", wantProto: ProtoDoT, wantAddr: "1.1.1.1:853"},
		{name: "tls alias", in: "tls://1.1.1.1:853", wantProto: ProtoDoT, wantAddr: "1.1.1.1:853"},
		{name: "doh full url", in: "https://cloudflare-dns.com/dns-query", wantProto: ProtoDoH, wantAddr: "https://cloudflare-dns.com/dns-query"},
		{name: "doh scheme alias", in: "doh://cloudflare-dns.com/dns-query", wantProto: ProtoDoH, wantAddr: "https://cloudflare-dns.com/dns-query"},
		{name: "ipv6 bracketed", in: "udp://[2606:4700:4700::1111]:53", wantProto: ProtoUDP, wantAddr: "[2606:4700:4700::1111]:53"},
		{name: "case insensitive scheme", in: "UDP://1.1.1.1:53", wantProto: ProtoUDP, wantAddr: "1.1.1.1:53"},
		{name: "empty rejected", in: "", wantErr: true},
		{name: "unsupported scheme", in: "ftp://1.1.1.1:53", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseResolverURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got cfg=%+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Protocol != tc.wantProto {
				t.Fatalf("Protocol: got %q, want %q", cfg.Protocol, tc.wantProto)
			}
			if cfg.Address != tc.wantAddr {
				t.Fatalf("Address: got %q, want %q", cfg.Address, tc.wantAddr)
			}
		})
	}
}
