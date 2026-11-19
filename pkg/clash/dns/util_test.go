package dns

import (
	"context"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type stubDnsClient struct {
	delay time.Duration
	rcode int
	ip    net.IP
	err   error
}

func (s *stubDnsClient) GetServers() []string { return []string{"stub"} }
func (s *stubDnsClient) Exchange(m *D.Msg) (*D.Msg, error) {
	return s.ExchangeContext(context.Background(), m)
}
func (s *stubDnsClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	resp := new(D.Msg)
	resp.SetReply(m)
	resp.Rcode = s.rcode
	if s.ip != nil {
		resp.Answer = append(resp.Answer, &D.A{
			Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   s.ip,
		})
	}
	return resp, nil
}

func TestBatchExchange_NXDOMAINDoesNotBeatSuccess(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("wpad.", D.TypeA)

	fastNX := &stubDnsClient{delay: 0, rcode: D.RcodeNameError}
	slowOK := &stubDnsClient{delay: 30 * time.Millisecond, rcode: D.RcodeSuccess, ip: net.ParseIP("10.1.2.3").To4()}

	resp, err := batchExchange(context.Background(), []dnsClient{fastNX, slowOK}, q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Rcode != D.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
	}
	ips := msgToIP(resp)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("expected [10.1.2.3], got %v", ips)
	}
}

func TestBatchExchange_AllNXDOMAINReturnsNXDOMAIN(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("nonexistent.local.", D.TypeA)

	c1 := &stubDnsClient{rcode: D.RcodeNameError}
	c2 := &stubDnsClient{delay: 10 * time.Millisecond, rcode: D.RcodeNameError}

	resp, err := batchExchange(context.Background(), []dnsClient{c1, c2}, q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Rcode != D.RcodeNameError {
		t.Fatalf("expected RcodeNameError, got %d", resp.Rcode)
	}
}
