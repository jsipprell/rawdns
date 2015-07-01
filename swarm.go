package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type swarmServiceDiscovery struct {
	Config DomainConfig
	Domain string
	Suffix string

	DiscoURL     string
	domainSuffix string

	httpClient       *http.Client
	leaderURL        *url.URL
	relaxedNamespace bool
}

func (sd *swarmServiceDiscovery) init(relaxedMode bool) {
	sd.domainSuffix = "." + dns.Fqdn(sd.Domain)
	sd.relaxedNamespace = relaxedMode
	transport := &http.Transport{}
	sd.httpClient = &http.Client{Transport: transport}

	u, err := url.Parse(sd.DiscoURL)
	if err != nil {
		panic(err)
	}

	if sd.Config.Port > 0 {
		parts := strings.SplitN(u.Host, ":", 2)
		u.Host = parts[0] + ":" + strconv.FormatUint(uint64(sd.Config.Port), 10)
	}
	u.Path = "/v1/kv/docker/swarm/leader"
	params := u.Query()
	params.Set("raw", "true")
	u.RawQuery = params.Encode()
	sd.leaderURL = u
}

func (sd *swarmServiceDiscovery) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var count int
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	for _, q := range r.Question {
		if rrs, err := CacheGetRR(q); err == nil && len(rrs) > 0 {
			for _, rr := range rrs {
				dnsAppend(q, m, rr, rr.Header().Name)
				count++
			}
			continue
		}
		name := q.Name
		qtype := q.Qtype

		if !strings.HasSuffix(name, sd.domainSuffix) {
			log.Printf("error: request for unknown domain %q (in %q)\n", name, sd.Domain)
			m.SetRcode(r, dns.RcodeNameError)
			return
		}
		name = strings.TrimSuffix(name, sd.domainSuffix)

		if qtype != dns.TypeSRV && qtype != dns.TypeCNAME && qtype != dns.TypeA {
			log.Printf("error: request for %v is not a supported rrtype for service discovery (%v: %q in %q)", qtype, name, sd.Domain)
			m.SetRcode(r, dns.RcodeNameError)
			return
		}

		switch strings.ToLower(name) {
		case "leader":
			if !sd.relaxedNamespace {
				break
			}
			fallthrough
		case "_leader":
			fallthrough
		case "_leader-http":
			var resp *http.Response
			var hostPort uint64
			var target string
			var err error
			for i := 0; i < 2; i++ {
				//log.Printf("URL: %v", sd.leaderURL.String())
				resp, err = sd.httpClient.Get(sd.leaderURL.String())
				//log.Printf("GOT: %+v, %v", resp, err)
				if resp != nil && resp.Body != nil {
					defer resp.Body.Close()
				}
				if err == nil {
					break
				}
			}
			if err == nil {
				var b []byte
				b, err = ioutil.ReadAll(resp.Body)
				//log.Printf("BODY: %q",string(b))
				if err == nil {
					parts := strings.SplitN(string(bytes.TrimSpace(b)), ":", 2)
					if len(parts) == 2 && len(parts[1]) > 0 {
						if hostPort, err = strconv.ParseUint(parts[1], 10, 16); err == nil {
							target = dns.Fqdn(parts[0])
						}
					} else if len(parts[0]) > 0 {
						target = dns.Fqdn(parts[0])
					}
				}
				if err == nil && target != "" {
					switch qtype {
					case dns.TypeSRV:
						srv := &dns.SRV{Port: uint16(hostPort), Target: target}
						//log.Printf("RR: %+v", srv)
						dnsAppend(q, m, srv)
						CachePutRRminTTL(2, srv)
						count++
					case dns.TypeA, dns.TypeCNAME:
						cname := &dns.CNAME{Target: target}
						//log.Printf("RR: %+v", cname)
						dnsAppend(q, m, cname)
						CachePutRRminTTL(2, cname)
						count++
					}
				}
			}
			if err != nil {
				log.Printf("error: %v (%v: %q in %q)", err, qtype, name, sd.Domain)
				m.SetRcode(r, dns.RcodeServerFailure)
				return
			}
		}
	}
	if count == 0 {
		m.SetRcode(r, dns.RcodeNameError)
	}
}
