package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const DNSSDLabelPrefix = "com.mcclatchy"

type Config map[string]DomainConfig // { "docker.": { ... }, ".": { ... } }

type DomainConfig struct {
	Type string `json:"type"` // "containers", "forwarding", "static"
	Port int    `json:"port"` // "swarm.dns-sd"

	// "type": "fail"
	Code string `json:"code"` // "fail"
	// "type": "containers"
	Socket string `json:"socket"` // "unix:///var/run/docker.sock"

	// "type": "forwarding"
	Nameservers []string `json:"nameservers"` // [ "8.8.8.8", "8.8.4.4" ]

	// "type": "static"
	Addrs  []string   `json:"addrs"`
	Cnames []string   `json:"cnames"`
	Txts   [][]string `json:"txts"`
	// pre-calculated/parsed
	addrs  []net.IP   // net.ParseIP(Addrs)
	cnames []string   // dns.Fqdn(Cnames)
	txts   [][]string // strings.Replace(Txts, `\`, `\\`, -1)
}

type serviceDiscoveryHandler struct {
	Config DomainConfig
	Domain string
	Suffix string

	domainSuffix string
}

var (
	config           Config
	broadcastAddress string
	tlsSettings      = struct {
		Enabled        bool
		CAFile         string
		VerifyCA       bool
		ClientCertFile string
		ClientKeyFile  string
	}{}

	tlsConfig *tls.Config
)

func cleanPath(p string) string {
	return filepath.Clean(p)
}

func isDir(p string) bool {
	if fi, err := os.Stat(cleanPath(p)); err == nil {
		return fi.IsDir()
	}
	return false
}

func isFile(p string) bool {
	if fi, err := os.Stat(cleanPath(p)); err == nil {
		return fi.Mode().IsRegular()
	}
	return false
}

func init() {
	cafile := "~/.docker/ca.pem"
	tlscert := "~/.docker/cert.pem"
	tlskey := "~/.docker/cert.key"

	broadcastAddress = os.Getenv("BROADCAST")
	if certDir := os.Getenv("DOCKER_CERT_PATH"); certDir != "" && isDir(certDir) {
		var try string

		certDir = cleanPath(certDir)
		if try = filepath.Join(certDir, filepath.Base(cafile)); isFile(try) {
			cafile = try
		}
		if try = filepath.Join(certDir, "client.pem"); isFile(try) {
			tlscert = try
		} else if try = filepath.Join(certDir, filepath.Base(tlscert)); isFile(try) {
			tlscert = try
		}
		if try = filepath.Join(certDir, "client-key.pem"); isFile(try) {
			tlskey = try
		} else if try = filepath.Join(certDir, filepath.Base(tlskey)); isFile(try) {
			tlskey = try
		}
	}
	flag.BoolVar(&tlsSettings.Enabled, "tls", false, "enable tls remote docker api")
	flag.StringVar(&tlsSettings.CAFile, "tlscacert", cafile, "Use specific CA certificate")
	flag.StringVar(&tlsSettings.ClientCertFile, "tlscert", tlscert, "Use specific TLS client certificate")
	flag.StringVar(&tlsSettings.ClientKeyFile, "tlskey", tlskey, "Use specific TLS client key")
	flag.BoolVar(&tlsSettings.VerifyCA, "tlsverify", false, "verify server certificate (implies -tls)")
}

func finalizeTLSConfig() []string {
	if !flag.Parsed() {
		flag.Parse()
	}
	if tlsSettings.VerifyCA {
		tlsSettings.Enabled = true
	}
	if tlsSettings.Enabled {
		tlsConfig = &tls.Config{
			Certificates: make([]tls.Certificate, 0, 1),
			MinVersion:   tls.VersionTLS10,
		}

		if tlsSettings.VerifyCA {
			if !isFile(tlsSettings.CAFile) {
				log.Fatal("-tlsverify requires a valid CA certificate (see -tlscacert)")
			}
			certPool := x509.NewCertPool()
			file, err := ioutil.ReadFile(tlsSettings.CAFile)
			if err != nil {
				log.Fatal(err)
			}
			certPool.AppendCertsFromPEM(file)
			tlsConfig.RootCAs = certPool
		} else {
			tlsConfig.InsecureSkipVerify = true
		}
		if isFile(tlsSettings.ClientCertFile) {
			if !isFile(tlsSettings.ClientKeyFile) {
				log.Fatal("-tlscert requires a tls key file (see -tlskey)")
			}
			cert, err := tls.LoadX509KeyPair(tlsSettings.ClientCertFile, tlsSettings.ClientKeyFile)
			if err != nil {
				log.Fatal(err)
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		} else if isFile(tlsSettings.ClientKeyFile) {
			log.Fatal("-tlskey requires a tls cert file (see -tlscert)")
		}
	}

	if tlsConfig != nil {
		log.Printf("TLS enabled: %+v", tlsConfig)
	}
	return flag.Args()
}

func main() {
	dnssdRe := regexp.MustCompile(`^(_[a-z]+)\.\w+`)

	log.Printf("rawdns v%s (%s on %s/%s; %s)\n", VERSION, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.Compiler)
	args := finalizeTLSConfig()

	configFile := "example-config.json"
	if len(args) > 0 {
		configFile = args[0]
	}
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("error: unable to read config file %s: %v\n", configFile, err)
	}
	err = json.Unmarshal(configData, &config)
	if err != nil {
		log.Fatalf("error: unable to process config file data from %s: %v\n", configFile, err)
	}

	for domain := range config {
		switch config[domain].Type {
		case "fail", "failed", "failing":
			code := dns.RcodeServerFailure
			s := config[domain].Code
			if s != "" {
				var ok bool
				if code, ok = dns.StringToRcode[strings.ToUpper(s)]; !ok {
					log.Fatalf("error: unknown rcode %q", strings.ToUpper(s))
				}
			}
			dCopy := domain
			dns.HandleFunc(dCopy, func(w dns.ResponseWriter, r *dns.Msg) {
				handleFailure(dCopy, code, w, r)
			})
		case "dns-sd":
			// DNS service discovery (aka _foobar-service._tcp.example.com)
			m := dnssdRe.FindStringSubmatch(domain)
			if len(m) < 2 {
				log.Fatalf("error: DNS-SD serviced domains must be in the form _tcp.<domain>, _udp.<domain> or similar")
			}
			sd := &serviceDiscoveryHandler{Config: config[domain], Domain: domain, Suffix: m[1]}
			sd.init()
			dns.Handle(domain, sd)
		case "swarm.dns-sd", "swarm":
			var suffix, discoveryURL string
			discovery := os.Getenv("SWARM_DISCOVERY")
			if discovery == "" {
				if discovery = os.Getenv("SWARM_ENV_SWARM_DISCOVERY"); discovery == "" {
					if discovery = os.Getenv("CFG_ENV_IPADDRESS"); discovery != "" {
						discovery = "consul://" + discovery + ":8500"
					}
				}
			}
			if discovery == "" {
				log.Fatal("swarm.dns-sd (swarm service discovery) not supported unless linked to swarm container or SWARM_DISCOVERY env variable is set")
			}
			if strings.HasPrefix(discovery, "consul://") {
				discoveryURL = "http://" + strings.TrimPrefix(discovery, "consul://")
			} else if strings.HasPrefix(discovery, "tcp://") {
				discoveryURL = "http://" + strings.TrimPrefix(discovery, "tcp://")
			} else if strings.HasPrefix(discovery, "http://") || strings.HasPrefix(discovery, "https://") {
				discoveryURL = discovery
			} else {
				log.Fatalf("swarm.dns-sd: %q is not a support swarm discovery url.", discovery)
			}
			isdnssd := strings.HasSuffix(config[domain].Type, ".dns-sd")
			if isdnssd {
				m := dnssdRe.FindStringSubmatch(domain)
				if len(m) < 2 {
					log.Fatalf("error: DNS-SD service domains must be in the form _tcp.<domain>, _udp.<domain> or similar")
				}
				suffix = m[1]
			}
			sd := &swarmServiceDiscovery{Config: config[domain], Domain: domain, Suffix: suffix, DiscoURL: discoveryURL}
			sd.init(!isdnssd)
			dns.Handle(domain, sd)
		case "containers":
			// TODO there must be a better way to pass "domain" along without an anonymous function AND copied variable
			dCopy := domain
			dns.HandleFunc(dCopy, func(w dns.ResponseWriter, r *dns.Msg) {
				handleDockerRequest(dCopy, w, r)
			})
		case "forwarding":
			// TODO there must be a better way to pass "domain" along without an anonymous function AND copied variable
			nameservers := config[domain].Nameservers

			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleForwarding(nameservers, w, r)
			})
		case "passthrough", "passthru":
			dnscfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				log.Fatalf("%q - cannot parse resolver config: %v", domain, err)
			}
			if len(dnscfg.Servers) == 0 {
				log.Fatalf("%q - /etc/resolv.conf contains no servers", domain)
			}

			nameservers := make([]string, len(config[domain].Nameservers), len(config[domain].Nameservers)+len(dnscfg.Servers))
			copy(nameservers, config[domain].Nameservers)

			nameservers = append(nameservers, dnscfg.Servers...)
			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleForwarding(nameservers, w, r)
			})
		case "static":
			cCopy := config[domain]

			cCopy.addrs = make([]net.IP, len(cCopy.Addrs))
			for i, addr := range cCopy.Addrs {
				cCopy.addrs[i] = net.ParseIP(addr)
			}

			cCopy.cnames = make([]string, len(cCopy.Cnames))
			for i, cname := range cCopy.Cnames {
				cCopy.cnames[i] = dns.Fqdn(cname)
			}

			cCopy.txts = make([][]string, len(cCopy.Txts))
			for i, txts := range cCopy.Txts {
				cCopy.txts[i] = make([]string, len(txts))
				for j, txt := range txts {
					cCopy.txts[i][j] = strings.Replace(txt, `\`, `\\`, -1)
				}
			}

			dns.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
				handleStaticRequest(cCopy, w, r)
			})
		default:
			log.Printf("error: unknown domain type on %s: %q\n", domain, config[domain].Type)
			continue
		}
		log.Printf("listening on domain: %s\n", domain)
	}

	udpListen := os.Getenv("UDP_LISTEN_ADDR")
	if udpListen == "" {
		udpListen = ":53"
	}
	tcpListen := os.Getenv("TCP_LISTEN_ADDR")
	if tcpListen == "" {
		tcpListen = udpListen
	}
	go serve("tcp", tcpListen)
	go serve("udp", udpListen)

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, os.Kill)
	for {
		select {
		case s := <-sig:
			log.Fatalf("fatal: signal %s received\n", s)
		}
	}
}

func serve(net, addr string) {
	server := &dns.Server{Addr: addr, Net: net, TsigSecret: nil}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to setup the %s server: %v\n", net, err)
	}
}

func dnsAppend(q dns.Question, m *dns.Msg, rr dns.RR, names ...string) {
	var hdr dns.RR_Header
	var extra, answer bool

	if len(names) > 0 {
		name := names[0]
		hdr = dns.RR_Header{Name: name, Class: q.Qclass, Ttl: 0}
		if name != q.Name {
			extra = true
		}
	} else {
		hdr = dns.RR_Header{Name: q.Name, Class: q.Qclass, Ttl: 0}
	}

	answer = q.Qtype == dns.TypeANY

	if rrS, ok := rr.(*dns.A); ok {
		hdr.Rrtype = dns.TypeA
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.AAAA); ok {
		hdr.Rrtype = dns.TypeAAAA
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.CNAME); ok {
		hdr.Rrtype = dns.TypeCNAME
		rrS.Hdr = hdr
		if !answer {
			answer = (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypePTR)
		}
	} else if rrS, ok := rr.(*dns.TXT); ok {
		hdr.Rrtype = dns.TypeTXT
		rrS.Hdr = hdr
	} else if rrS, ok := rr.(*dns.SRV); ok {
		hdr.Rrtype = dns.TypeSRV
		rrS.Hdr = hdr
	} else {
		log.Printf("error: unknown dnsAppend RR type: %+v\n", rr)
		return
	}

	if !extra && (answer || (q.Qtype == dns.TypeANY || q.Qtype == rr.Header().Rrtype)) {
		m.Answer = append(m.Answer, rr)
	} else {
		m.Extra = append(m.Extra, rr)
	}
}

func normalizeContainerName(upcaseprefix bool, name string, suffixes ...string) string {
	if upcaseprefix {
		name = strings.ToUpper(name)
	} else {
		name = strings.ToLower(name)
	}
	for i, s := range suffixes {
		suffixes[i] = strings.ToLower(s)
	}

	suffixes = append(suffixes, name)
	copy(suffixes[1:], suffixes)
	suffixes[0] = name

	return strings.Join(suffixes, "/")
}

func (sd *serviceDiscoveryHandler) init() {
	sd.domainSuffix = "." + dns.Fqdn(sd.Domain)
}

func (sd *serviceDiscoveryHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var count int
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	fakearecs := make(map[string]string)
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

		if qtype != dns.TypeA && qtype != dns.TypeSRV {
			log.Printf("error: request for %v is not a supported rrtype for service discovery (%v: %q in %q)", qtype, name, sd.Domain)
			m.SetRcode(r, dns.RcodeNameError)
			return
		}
		filt := make(map[string][]string)
		label := strings.ToLower(DNSSDLabelPrefix + "." + sd.Suffix + "." + name)
		filt["label"] = []string{label}
		C, err := dockerInspectContainers(sd.Config.Socket, filt)
		if err != nil {
			log.Printf("error: %v (%v: %q in %q)", err, qtype, name, sd.Domain)
			m.SetRcode(r, dns.RcodeServerFailure)
			return
		}

		for container := range C {
			var labelPort string
			var pri, weight uint16

			if lp, ok := container.Config.Labels[label]; ok {
				if strings.ContainsAny(lp, ":") {
					parts := strings.Split(lp, ":")
					lp = parts[0]
					if parts[1] != "" {
						if iv, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
							if iv > 0 {
								pri = uint16(iv)
							} else {
								pri = 1
							}
						}
					}
					if len(parts) > 2 && parts[2] != "" {
						if iv, err := strconv.ParseUint(parts[2], 10, 16); err == nil {
							if iv > 0 {
								weight = uint16(iv)
							} else {
								weight = 1
							}
						}
					}
				}
				labelPort = lp + "/" + strings.ToLower(sd.Suffix[1:])
			} else {
				continue
			}
			for nport, dest := range container.NetworkSettings.Ports {
				if labelPort != "" && strings.ToLower(nport) != labelPort {
					log.Printf("ignoring port %q (no match with label port %q)", nport, labelPort)
					continue
				}
				for _, host := range dest {
					target := host.IpAddress
					if target == "0.0.0.0" && broadcastAddress != "" {
						target = broadcastAddress
					}
					if targetIp := net.ParseIP(target); targetIp != nil {
						fakeName, ok := fakearecs[targetIp.String()]
						if !ok {
							names, err := net.LookupAddr(targetIp.String())
							if err == nil && len(names) > 0 {
								fakeName = names[0]
								fakearecs[targetIp.String()] = fakeName
							}
						}
						target = fakeName
					}
					if target != "" && !strings.HasSuffix(target, ".") {
						target += "."
					}
					if hostPort, err := strconv.ParseUint(host.Port, 10, 16); hostPort > 0 && err == nil {
						srv := &dns.SRV{Port: uint16(hostPort), Target: target, Priority: pri, Weight: weight}
						dnsAppend(q, m, srv)
						CachePutRRminTTL(2, srv)
						count++
					}
				}
			}
		}
	}
	if count == 0 {
		m.SetRcode(r, dns.RcodeNameError)
	}
}

func handleDockerRequest(domain string, w dns.ResponseWriter, r *dns.Msg) {
	handleMultiDockerRequest(domain, w, r, func(sock string, names ...string) (<-chan *dockerContainer, error) {
		var name string

		if len(names) > 0 {
			name = names[0]
			names = names[1:]
		}
		if strings.HasPrefix(name, "filter_") {
			name = strings.Replace(name, "_", "=", -1)
		}
		if strings.HasPrefix(name, "filter=") {
			filters := strings.SplitAfter(name, "filter=")
			if len(filters) > 1 {
				fmap := make(map[string][]string)
				for _, f := range filters {
					if f == "filter=" {
						continue
					}
					kv := strings.SplitN(f, "=", 2)
					if len(kv) == 2 {
						fmap[kv[0]] = append(fmap[kv[0]], strings.TrimPrefix(kv[1], "="))
					}
				}
				if len(fmap) > 0 {
					log.Printf("dockerInspectContainers(%#v, %#v)", sock, fmap)
					return dockerInspectContainers(sock, fmap)
				}
			}
			return nil, fmt.Errorf("no containers matched expression %#v", name)
		}
		container, err := dockerInspectContainer(sock, normalizeContainerName(false, name, names...))
		if err != nil {
			container, err = dockerInspectContainer(sock, normalizeContainerName(true, name, names...))
		}
		if err != nil {
			return nil, err
		}
		C := make(chan *dockerContainer, 2)
		C <- container
		close(C)
		return C, nil
	})
}

func handleMultiDockerRequest(domain string, w dns.ResponseWriter, r *dns.Msg,
	getContainers func(string, ...string) (<-chan *dockerContainer, error)) {

	var count int
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	domainSuffix := "." + dns.Fqdn(domain)
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

		if !strings.HasSuffix(name, domainSuffix) {
			log.Printf("error: request for unknown domain %q (in %q)\n", name, domain)
			return
		}
		containerName := name[:len(name)-len(domainSuffix)]

		C, err := getContainers(config[domain].Socket, containerName)
		if err != nil && strings.Contains(containerName, ".") {
			// we have something like "db.app", so let's try looking up a "app/db" container (linking!)
			parts := strings.Split(containerName, ".")
			rparts := make([]string, len(parts))
			for i, p := range parts {
				rparts[len(parts)-(i+1)] = p
			}
			C, err = getContainers(config[domain].Socket, rparts...)
		}
		if err != nil {
			log.Printf("error: failed to lookup container %q: %v\n", containerName, err)
			return
		}

		for container := range C {
			containerIp := container.NetworkSettings.IpAddress
			if containerIp == "" {
				log.Printf("error: container %q is IP-less\n", containerName)
				return
			}

			if qtype == dns.TypeA || qtype == dns.TypeANY {
				var a *dns.A
				if container.PublicIpAddress != nil {
					a = &dns.A{A: container.PublicIpAddress}
				} else {
					a = &dns.A{A: net.ParseIP(containerIp)}
				}
				dnsAppend(q, m, a)
				CachePutRRminTTL(2, a)
			}
			if len(container.NetworkSettings.Ports) > 0 {
				portcfg := make([]string, 0, len(container.NetworkSettings.Ports))
				if qtype == dns.TypeANY || qtype == dns.TypeTXT || qtype == dns.TypeSRV {
					for nport, dest := range container.NetworkSettings.Ports {
						if len(dest) > 0 {
							switch {
							case qtype == dns.TypeANY || qtype == dns.TypeTXT:
								portcfg = append(portcfg, nport)
								if qtype != dns.TypeANY {
									break
								}
								fallthrough
							case qtype == dns.TypeSRV:
								fakearecs := make(map[string]string)
								for _, host := range dest {
									target := host.IpAddress
									if target == "0.0.0.0" && broadcastAddress != "" {
										target = broadcastAddress
									}
									if targetIp := net.ParseIP(target); targetIp != nil {
										fakeName, ok := fakearecs[targetIp.String()]
										if !ok {
											names, err := net.LookupAddr(targetIp.String())
											if err == nil && len(names) > 0 {
												fakeName = names[0]
												fakearecs[targetIp.String()] = fakeName
											}
										}
										target = fakeName
									}
									if target != "" && !strings.HasSuffix(target, ".") {
										target += "."
									}
									if hostPort, err := strconv.ParseUint(host.Port, 10, 16); hostPort > 0 && err == nil {
										srv := &dns.SRV{Port: uint16(hostPort), Target: target}
										dnsAppend(q, m, srv)
										CachePutRRminTTL(2, srv)
									}
								}
							}
						}
					}
				}
				if len(portcfg) > 0 {
					txt := &dns.TXT{Txt: portcfg}
					dnsAppend(q, m, txt)
					CachePutRRminTTL(2, txt)
				}
			}
		}
		//dnsAppend(q, m, &dns.AAAA{AAAA: net.ParseIP(container.NetworkSettings.Ipv6AddressesAsMultipleAnswerEntries)})
		// TODO IPv6 support (when Docker itself has such a thing...)
	}
}

func handleStaticRequest(config DomainConfig, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	for _, q := range r.Question {
		for _, addr := range config.addrs {
			if addr.To4() != nil { // "If ip is not an IPv4 address, To4 returns nil."
				a := &dns.A{A: addr}
				dnsAppend(q, m, a)
				CachePutRRminTTL(2, a)
			} else {
				a := &dns.AAAA{AAAA: addr}
				dnsAppend(q, m, a)
				CachePutRRminTTL(2, a)
			}
		}

		for _, cname := range config.cnames {
			cn := &dns.CNAME{Target: cname}
			dnsAppend(q, m, cn)
			CachePutRRminTTL(2, cn)
			if r.RecursionDesired && len(config.Nameservers) > 0 {
				recR := &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id: dns.Id(),
					},
					Question: []dns.Question{
						{Name: cname, Qtype: q.Qtype, Qclass: q.Qclass},
					},
				}
				if rrs, err := CacheGetRR(recR.Question...); err == nil && len(rrs) > 0 {
					for _, rr := range rrs {
						dnsAppend(q, m, rr)
					}
					continue
				}
				recM := handleForwardingRaw(config.Nameservers, recR, w.RemoteAddr())
				for _, rr := range recM.Answer {
					dnsAppend(q, m, rr)
					CachePutRR(rr)
				}
				for _, rr := range recM.Extra {
					dnsAppend(q, m, rr)
					CachePutRR(rr)
				}
			}
		}

		for _, txt := range config.txts {
			txt := &dns.TXT{Txt: txt}
			dnsAppend(q, m, txt)
			CachePutRRminTTL(2, txt)
		}
	}
}
