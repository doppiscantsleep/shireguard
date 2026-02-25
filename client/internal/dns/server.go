package dns

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/shireguard/shireguard/internal/api"
)

var nonAlphanumDash = regexp.MustCompile(`[^a-z0-9-]`)

// normalizeName converts a device name to a valid DNS label component.
// e.g. "Alan's MacBook Pro" → "alans-macbook-pro"
func normalizeName(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = nonAlphanumDash.ReplaceAllString(s, "")
	// Collapse multiple dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	return s
}

// Server is a lightweight DNS server that resolves *.shireguard names to
// WireGuard peer IPs. All other queries are forwarded upstream.
type Server struct {
	listenAddr string
	upstream   string
	srv        *dns.Server

	mu      sync.RWMutex
	records map[string]string // fqdn (lower, trailing dot) → IP
}

// New creates a new DNS Server that will listen on listenAddr.
func New(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
		upstream:   "1.1.1.1:53",
		records:    make(map[string]string),
	}
}

// Start begins serving DNS requests on the configured listen address.
func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc("shireguard.", s.handleDNS)
	mux.HandleFunc(".", s.forwardDNS)

	s.srv = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: mux,
	}

	ready := make(chan error, 1)
	s.srv.NotifyStartedFunc = func() { ready <- nil }

	go func() {
		if err := s.srv.ListenAndServe(); err != nil {
			select {
			case ready <- err:
			default:
			}
		}
	}()

	return <-ready
}

// Stop shuts down the DNS server.
func (s *Server) Stop() {
	if s.srv != nil {
		_ = s.srv.Shutdown()
	}
}

// SetPeers rebuilds the DNS records from the current peer list.
// selfName and selfIP are used to register this device's own name.
func (s *Server) SetPeers(peers []api.Peer, selfName, selfIP string) {
	newRecords := make(map[string]string, len(peers)+1)

	addRecord := func(name, ip string) {
		normalized := normalizeName(name)
		if normalized == "" {
			return
		}
		fqdn := normalized + ".shireguard."
		newRecords[fqdn] = ip
	}

	for _, p := range peers {
		addRecord(p.Name, p.AssignedIP)
	}
	if selfName != "" && selfIP != "" {
		addRecord(selfName, selfIP)
	}

	s.mu.Lock()
	s.records = newRecords
	s.mu.Unlock()
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		if q.Qtype != dns.TypeA {
			// For non-A queries within .shireguard, return no records (NOERROR)
			continue
		}
		fqdn := strings.ToLower(q.Name)

		s.mu.RLock()
		ip, ok := s.records[fqdn]
		s.mu.RUnlock()

		if !ok {
			m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			_ = w.WriteMsg(m)
			return
		}

		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(ip).To4(),
		}
		m.Answer = append(m.Answer, rr)
	}

	_ = w.WriteMsg(m)
}

func (s *Server) forwardDNS(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)
	resp, _, err := c.Exchange(r, s.upstream)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	_ = w.WriteMsg(resp)
}
