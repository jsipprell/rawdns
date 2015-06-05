package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testEnableCache() {
	EnableCache = true
}

func TestDNSCaching(t *testing.T) {
	testEnableCache()
	a, err := dns.NewRR("testies. IN A 192.10.1.2")
	if err != nil {
		t.Fatal(err)
	}
	a.Header().Ttl = uint32(3)
	t.Logf("A: %v", a)
	if err = CachePutRR(a); err != nil {
		t.Fatal(err)
	}

	a = &dns.A{
		Hdr: dns.RR_Header{
			Name:   "testies.",
			Rrtype: dns.TypeANY,
		},
	}
	t.Logf("Q: %v", a)

	time.Sleep(time.Duration(3001) * time.Millisecond)
	rrset, err := CacheGetRR(a)
	if err != nil {
		t.Fatal(err)
	}

	for _, rr := range rrset {
		t.Logf("GOT: %v", rr)
	}
}
