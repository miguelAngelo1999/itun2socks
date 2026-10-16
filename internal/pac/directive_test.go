package pac

import "testing"

func TestParseDirectives(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []Directive
	}{
		{"direct", "DIRECT", []Directive{{Scheme: "direct"}}},
		{"proxy http", "PROXY 10.0.0.1:8080", []Directive{{Scheme: "http", Host: "10.0.0.1", Port: "8080"}}},
		{"lowercase proxy", "proxy 10.0.0.1:8080", []Directive{{Scheme: "http", Host: "10.0.0.1", Port: "8080"}}},
		{"socks5", "SOCKS5 10.0.0.2:1080", []Directive{{Scheme: "socks5", Host: "10.0.0.2", Port: "1080"}}},
		{"socks", "SOCKS 10.0.0.2:1080", []Directive{{Scheme: "socks5", Host: "10.0.0.2", Port: "1080"}}},
		{"http keyword", "HTTP proxy.example.com:3128", []Directive{{Scheme: "http", Host: "proxy.example.com", Port: "3128"}}},
		{
			"failover list",
			"PROXY 10.0.0.1:8080; SOCKS5 10.0.0.2:1080; DIRECT",
			[]Directive{
				{Scheme: "http", Host: "10.0.0.1", Port: "8080"},
				{Scheme: "socks5", Host: "10.0.0.2", Port: "1080"},
				{Scheme: "direct"},
			},
		},
		{"malformed proxy no addr falls back to direct", "PROXY", []Directive{{Scheme: "direct"}}},
		{"unknown keyword falls back to direct", "FOOBAR 1.2.3.4:5", []Directive{{Scheme: "direct"}}},
		{"empty falls back to direct", "", []Directive{{Scheme: "direct"}}},
		{"malformed first then valid", "PROXY ; SOCKS5 10.0.0.2:1080", []Directive{{Scheme: "socks5", Host: "10.0.0.2", Port: "1080"}}},
		{"host:port with no port skipped", "PROXY 10.0.0.1", []Directive{{Scheme: "direct"}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseDirectives(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len mismatch: got %+v want %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("idx %d: got %+v want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}
