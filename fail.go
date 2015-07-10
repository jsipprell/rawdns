package main

import (
	"github.com/miekg/dns"
)

func handleFailure(domain string, rcode int, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	w.WriteMsg(m)
}
