// caching support for rawdns (optional)
package main

import (
	"container/list"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	cacheReqADD cacheReqOp = iota
	cacheReqGET
	cacheReqDEL
)

type cacheReqOp int

type cacheQuestion struct {
	dns.Question

	hdr *dns.RR_Header
}

type rrTypeCacheIndex map[string]*list.Element

type rrSet []dns.RR

type cacher struct {
	l          *list.List
	index      rrTypeCacheIndex
	cacheReqCh chan *cacheReq

	lastExpire time.Time
}

type cacheReq struct {
	op       cacheReqOp
	selector func(dns.RR) bool
	q        []cacheQuestion
	gate     chan struct{}
	err      error
	rr       []dns.RR
}

var (
	ErrNoCache = errors.New("no cache")

	EnableCache bool
	cacheSem    chan struct{}
	cache       *cacher
)

func init() {
	cacheSem = make(chan struct{}, 1)
	cacheSem <- struct{}{}

	EnableCache = os.Getenv("CACHE") != ""
}

func (q *cacheQuestion) Header() *dns.RR_Header {
	if q.hdr == nil {
		q.hdr = &dns.RR_Header{
			Name:   dns.Fqdn(q.Name),
			Rrtype: q.Qtype,
			Class:  q.Qclass,
		}
	}

	return q.hdr
}

func (c *cacher) getHdr(hdr *dns.RR_Header, add bool) *list.Element {
	name := strings.ToLower(hdr.Name)
	e, ok := c.index[name]
	if !ok && add {
		e = c.l.PushFront(nil)
		c.index[name] = e
	}
	return e
}

func (c *cacher) expire(now time.Time) {

	if now.IsZero() {
		now = time.Now()
	}
	upd := now.Sub(c.lastExpire)
	defer func(t time.Time) {
		c.lastExpire = t
	}(now)

	for e := c.l.Front(); e != nil; e = e.Next() {
		if set, ok := e.Value.(rrSet); ok {
			var count int
			var name string

			if len(set) == 0 {
				defer c.l.Remove(e)
				continue
			}

			for _, rr := range set {
				hdr := rr.Header()
				if name == "" {
					name = strings.ToLower(hdr.Name)
				}
				ttl := (time.Duration(hdr.Ttl)*time.Second + 1) - upd
				if ttl <= 0 {
					ttl = 0
				}
				hdr.Ttl = uint32(ttl / time.Second)
				if hdr.Ttl == 0 && uint32(ttl%time.Second) == 0 {
					count++
				}
			}
			if count > 0 {
				nset := make(rrSet, 0, len(set)-count)
				for _, rr := range set {
					if rr.Header().Ttl != 0 {
						nset = append(nset, rr)
					}
				}
				e.Value = nset
				if len(nset) == 0 {
					defer c.l.Remove(e)
					if name != "" {
						delete(c.index, name)
					}
				}
			}
		}
	}
}

func (c *cacher) match(rr dns.RR, hdr *dns.RR_Header) bool {
	if h := rr.Header(); h != nil {
		if hdr.Rrtype == dns.TypeANY || hdr.Rrtype == h.Rrtype {
			return hdr.Class == 0 || hdr.Class == h.Class
		}
	}

	return false
}

func (c *cacher) handle(r *cacheReq) {
	defer close(r.gate)
	switch r.op {
	case cacheReqADD:
		for _, rr := range r.rr {
			if elem := c.getHdr(rr.Header(), false); elem != nil {
				if v, ok := elem.Value.(rrSet); ok && v != nil {
					elem.Value = append(v, dns.Copy(rr))
					continue
				}
			}
			set := make(rrSet, 1)
			set[0] = dns.Copy(rr)
			c.index[strings.ToLower(rr.Header().Name)] = c.l.PushFront(set)
		}
	case cacheReqGET:
		result := make([]dns.RR, 0, 1)
		for _, qr := range r.q {
			if elem := c.getHdr(qr.Header(), false); elem != nil {
				if set, ok := elem.Value.(rrSet); ok && len(set) > 0 {
					for _, i := range set {
						if r.selector != nil {
							if r.selector(dns.Copy(i)) {
								result = append(result, dns.Copy(i))
							}
						} else if c.match(i, qr.Header()) {
							result = append(result, dns.Copy(i))
						}
					}
				}
			}
		}
		r.rr = result
		if len(result) == 0 {
			r.err = ErrNoCache
		}
	case cacheReqDEL:
		count := 0
		for _, qr := range r.q {
			nset := make(rrSet, 0, 1)
			rrhdr := qr.Header()
			name := strings.ToLower(rrhdr.Name)
			if elem := c.getHdr(rrhdr, false); elem != nil {
				if set, ok := elem.Value.(rrSet); ok && len(set) > 0 {
					for _, i := range set {
						if name == "" {
							name = strings.ToLower(i.Header().Name)
						}
						if r.selector != nil && !r.selector(dns.Copy(i)) {
							nset = append(nset, i)
						} else if !c.match(i, rrhdr) {
							nset = append(nset, i)
						} else {
							count++
						}
					}
				}
				elem.Value = nset
				if len(nset) == 0 {
					defer c.l.Remove(elem)
					delete(c.index, name)
				}
			}
		}
		if count == 0 {
			r.err = ErrNoCache
		}
	}
}

func (c *cacher) run(done chan<- struct{}) {
	defer func() {
		done <- struct{}{}
	}()

	c.l = list.New()
	c.index = make(rrTypeCacheIndex)
	c.lastExpire = time.Now()

	ticker := time.NewTicker(time.Duration(1) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case r, ok := <-c.cacheReqCh:
			if !ok {
				return
			}
			c.handle(r)
		case t := <-ticker.C:
			c.expire(t)
		}
	}
}

func getCacheReqCh() chan<- *cacheReq {
	select {
	case <-cacheSem:
		cache = &cacher{cacheReqCh: make(chan *cacheReq, 1)}
		go cache.run(cacheSem)
	default:
	}

	return cache.cacheReqCh
}

func CacheGetRR(qrs ...dns.Question) ([]dns.RR, error) {
	if !EnableCache {
		return nil, ErrNoCache
	}

	q := make([]cacheQuestion, len(qrs))
	for i, qr := range qrs {
		q[i] = cacheQuestion{Question: qr}
	}
	req := &cacheReq{
		op:   cacheReqGET,
		gate: make(chan struct{}, 0),
		q:    q,
	}
	getCacheReqCh() <- req
	<-req.gate

	return req.rr, req.err
}

func CachePutRR(rrs ...dns.RR) error {
	if !EnableCache {
		return ErrNoCache
	}

	req := &cacheReq{
		op:   cacheReqADD,
		gate: make(chan struct{}, 0),
		rr:   rrs,
	}

	getCacheReqCh() <- req
	<-req.gate
	return req.err
}

func CachePutRRminTTL(minTTL uint32, rrs ...dns.RR) error {
	for _, rr := range rrs {
		hdr := rr.Header()
		if hdr.Ttl < minTTL {
			hdr.Ttl = minTTL
		}
	}

	if !EnableCache {
		return ErrNoCache
	}

	req := &cacheReq{
		op:   cacheReqADD,
		gate: make(chan struct{}, 0),
		rr:   rrs,
	}

	getCacheReqCh() <- req
	<-req.gate
	return req.err
}

func CacheRemoveRR(qrs ...dns.Question) error {
	if !EnableCache {
		return ErrNoCache
	}

	q := make([]cacheQuestion, len(qrs))
	for i, qr := range qrs {
		q[i] = cacheQuestion{Question: qr}
	}

	req := &cacheReq{
		op:   cacheReqDEL,
		gate: make(chan struct{}, 0),
		q:    q,
	}

	getCacheReqCh() <- req
	<-req.gate
	return req.err
}
