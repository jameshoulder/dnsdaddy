// Command dnsdaddy-lab generates deterministic synthetic DNS traffic for
// demonstrating and testing DNS Daddy's behavioural detections.
//
// # Safety
//
// This tool never contacts malicious infrastructure and never needs to. Every
// name it emits sits under .example or .test, which RFC 2606 and RFC 6761
// reserve for documentation and testing and which are not delegated in the
// root zone. No attacker learns anything, and the scenarios are reproducible
// on a laptop with no internet connection at all.
//
// That is a deliberate design constraint rather than a limitation. A detection
// lab that depends on live malware C2 is a lab that stops working when the
// infrastructure is taken down, and one that puts the person running it in
// contact with real attackers to prove a heuristic fires.
//
// # The responder
//
// Run with -sink, this same binary serves the lab's synthetic zone, and DNS
// Daddy is pointed at it as its upstream. That does two things. It keeps the
// lab entirely offline — no synthetic query leaves the machine. And it makes
// the traffic realistic: the attacker's tunnel domain resolves, as it must for
// a tunnel to work, while a generation algorithm's candidates do not. Sending
// the scenarios to a public resolver instead would fail every lookup equally,
// because .example is not delegated, and each scenario would raise a spurious
// NXDOMAIN finding on top of the one it was built to show.
//
// # Determinism
//
// Everything is driven by a seeded PRNG and a fixed schedule. The same seed
// produces the same names in the same order, so a demonstration recorded today
// can be reproduced exactly next month, and a screenshot can be regenerated
// rather than reshot.
//
// # Client attribution
//
// On Linux the whole 127.0.0.0/8 range is local, so each scenario binds a
// different loopback source address and appears to DNS Daddy as a different
// client. That is what makes per-client findings meaningful in the lab. On
// platforms where only 127.0.0.1 is bound, pass -client 127.0.0.1 and expect
// every scenario to be attributed to the same device.
//
// Usage:
//
//	dnsdaddy-lab -sink 127.0.0.1:5300
//	dnsdaddy-lab -server 127.0.0.1:53 -scenario dns-tunnelling
//	dnsdaddy-lab -server 127.0.0.1:53 -scenario all -speed 10
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dnsdaddy-lab: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		server   = flag.String("server", "127.0.0.1:53", "resolver address to send queries to")
		scenario = flag.String("scenario", "", "scenario to run, or 'all'; omit to list them")
		seed     = flag.Int64("seed", 1, "PRNG seed; the same seed reproduces the same traffic exactly")
		speed    = flag.Float64("speed", 1, "time compression: 20 replays a 10-minute scenario in 30 seconds")
		client   = flag.String("client", "", "source address to bind, overriding the scenario's own")
		dry      = flag.Bool("dry-run", false, "print the queries without sending them")
		quiet    = flag.Bool("quiet", false, "suppress per-query output")
		sink     = flag.String("sink", "", "instead of generating traffic, run the lab's authoritative responder on this address")
	)
	flag.Parse()

	if *sink != "" {
		return runSink(*sink)
	}
	if *scenario == "" {
		listScenarios()
		return nil
	}
	if *speed <= 0 {
		return fmt.Errorf("-speed must be positive")
	}

	names := []string{*scenario}
	if *scenario == "all" {
		names = scenarioNames()
	}

	for _, name := range names {
		sc, ok := scenarios[name]
		if !ok {
			return fmt.Errorf("unknown scenario %q; run without -scenario to list them", name)
		}
		src := sc.Client
		if *client != "" {
			src = *client
		}
		if err := play(sc, *server, src, *seed, *speed, *dry, *quiet); err != nil {
			return fmt.Errorf("scenario %s: %w", name, err)
		}
	}
	return nil
}

// labZones are the registered domains the lab's responder treats as existing.
//
// Everything else gets NXDOMAIN, which is what makes the lab realistic rather
// than merely noisy. On a real network an attacker's tunnel domain resolves —
// it has to, or the tunnel does not work — while the thousand candidates a
// generation algorithm tries do not. Pointing the lab at a public resolver
// instead would NXDOMAIN all of it equally, because .example is not delegated,
// and every scenario would produce a spurious nxdomain_burst finding on top of
// the one it was designed to demonstrate.
//
// Running the responder also keeps the lab entirely offline: no synthetic
// query ever leaves the machine.
var labZones = map[string]uint32{
	// Ordinary browsing destinations, with ordinary TTLs.
	"news.example":       300,
	"shop.example":       300,
	"search.example":     300,
	"docs.example":       300,
	"mail.example":       300,
	"bank.example":       300,
	"gov.example":        300,
	"university.example": 300,
	"supplier.example":   3600,
	"widgets.example":    300,

	// Attacker-controlled domains. Short TTLs, as a tunnel wants.
	"tunnel.example": 60,
	"c2.example":     60,

	// The beacon's domain. The 300-second TTL is deliberately far from the
	// scenario's 45-second check-in period, so the beaconing detector's
	// TTL-driven-refresh suppression does not fire and the finding is raised
	// on the cadence itself.
	"beacon.example": 300,
}

// runSink serves the lab's synthetic zone.
//
// Not a real authoritative server and not trying to be: it answers enough for
// the resolver in front of it to produce realistic telemetry, and nothing
// else. It listens on UDP and TCP because a resolver will retry over TCP for a
// truncated answer.
func runSink(addr string) error {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true

		if len(req.Question) != 1 {
			m.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")

		ttl, known := zoneFor(name)
		if !known {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}

		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			// TEST-NET-3 (RFC 5737), reserved for documentation.
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(203, 0, 113, 42)}}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			// 2001:db8::/32, reserved for documentation (RFC 3849).
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::2a")}}
		case dns.TypeTXT:
			hdr.Rrtype = dns.TypeTXT
			m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"dnsdaddy-lab synthetic response"}}}
		default:
			// NOERROR with no answer: the name exists, this type does not.
		}
		_ = w.WriteMsg(m)
	})

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errs := make(chan error, 2)
	go func() { errs <- udp.ListenAndServe() }()
	go func() { errs <- tcp.ListenAndServe() }()

	fmt.Printf("lab responder listening on %s (udp+tcp)\n", addr)
	fmt.Printf("  %d synthetic zones; everything else answers NXDOMAIN\n", len(labZones))
	return <-errs
}

// zoneFor finds the lab zone a name belongs to, walking up its suffixes.
func zoneFor(name string) (uint32, bool) {
	for {
		if ttl, ok := labZones[name]; ok {
			return ttl, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return 0, false
		}
		name = name[i+1:]
	}
}

// query is one synthetic lookup at a point in the scenario's timeline.
type query struct {
	at    time.Duration
	name  string
	qtype uint16
}

// scenario is a reproducible traffic pattern.
type scenario struct {
	Name string
	// Client is the loopback source address this scenario binds, so DNS Daddy
	// attributes it to its own device.
	Client string
	// Detects names the finding this scenario is designed to produce, or is
	// empty where the scenario exists to show that nothing fires.
	Detects string
	Summary string
	// Duration is the scenario's simulated length before time compression.
	Duration time.Duration
	Build    func(r *rand.Rand) []query
}

const (
	base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	lowerAlphabet  = "abcdefghijklmnopqrstuvwxyz"
)

func randomLabel(r *rand.Rand, alphabet string, n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

var scenarios = map[string]scenario{
	"normal-dns": {
		Name:     "normal-dns",
		Client:   "127.0.0.2",
		Detects:  "",
		Summary:  "Ordinary browsing. Establishes the baseline and demonstrates that the detectors stay silent on it.",
		Duration: 6 * time.Minute,
		Build: func(r *rand.Rand) []query {
			sites := []string{
				"news.example", "shop.example", "search.example", "docs.example",
				"mail.example", "bank.example", "gov.example", "university.example",
			}
			hosts := []string{"www", "static", "api", "cdn", "assets", "images", "login"}
			types := []uint16{dns.TypeA, dns.TypeA, dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS}

			var out []query
			at := time.Duration(0)
			for at < 6*time.Minute {
				out = append(out, query{
					at:    at,
					name:  hosts[r.Intn(len(hosts))] + "." + sites[r.Intn(len(sites))],
					qtype: types[r.Intn(len(types))],
				})
				// Bursty, the way a person browsing is: a page load fires a
				// dozen lookups, then nothing for a while.
				if r.Intn(6) == 0 {
					at += time.Duration(2+r.Intn(25)) * time.Second
				} else {
					at += time.Duration(40+r.Intn(500)) * time.Millisecond
				}
			}
			return out
		},
	},

	"dns-tunnelling": {
		Name:     "dns-tunnelling",
		Client:   "127.0.0.3",
		Detects:  "dns_tunnel_suspected",
		Summary:  "An encoding tunnel: a fresh high-entropy name per message under one parent, over TXT.",
		Duration: 6 * time.Minute,
		Build: func(r *rand.Rand) []query {
			var out []query
			at := time.Duration(0)
			// Roughly one message per second for six minutes, which is a
			// modest tunnel — real tools go far faster.
			for at < 6*time.Minute {
				out = append(out, query{
					at: at,
					// Two long base32 labels: the payload, chunked to stay
					// inside the 63-byte label limit.
					name: fmt.Sprintf("%s.%s.tunnel.example",
						randomLabel(r, base32Alphabet, 55),
						randomLabel(r, base32Alphabet, 42)),
					qtype: dns.TypeTXT,
				})
				at += time.Duration(700+r.Intn(500)) * time.Millisecond
			}
			return out
		},
	},

	"high-entropy-subdomains": {
		Name:     "high-entropy-subdomains",
		Client:   "127.0.0.4",
		Detects:  "",
		Summary:  "High-entropy subdomains WITHOUT the other tunnel signals. Demonstrates the multi-signal gate: randomness alone does not raise a finding.",
		Duration: 6 * time.Minute,
		Build: func(r *rand.Rand) []query {
			// A small pool of genuinely random but short labels, reused, over
			// address lookups. Entropy is high; cardinality, name length,
			// record type and failure rate are all ordinary.
			pool := make([]string, 40)
			for i := range pool {
				pool[i] = randomLabel(r, base32Alphabet, 14)
			}
			var out []query
			at := time.Duration(0)
			for at < 6*time.Minute {
				out = append(out, query{
					at:    at,
					name:  pool[r.Intn(len(pool))] + ".widgets.example",
					qtype: dns.TypeA,
				})
				at += time.Duration(400+r.Intn(600)) * time.Millisecond
			}
			return out
		},
	},

	"nxdomain-anomaly": {
		Name:     "nxdomain-anomaly",
		Client:   "127.0.0.5",
		Detects:  "nxdomain_burst",
		Summary:  "A host failing hundreds of lookups across many unrelated domains in a few minutes.",
		Duration: 6 * time.Minute,
		Build: func(r *rand.Rand) []query {
			var out []query
			at := time.Duration(0)
			for at < 6*time.Minute {
				out = append(out, query{
					at: at,
					name: fmt.Sprintf("%s.%s.example",
						randomLabel(r, lowerAlphabet, 6+r.Intn(4)),
						randomLabel(r, lowerAlphabet, 8+r.Intn(6))),
					qtype: dns.TypeA,
				})
				at += time.Duration(300+r.Intn(400)) * time.Millisecond
			}
			return out
		},
	},

	"suspicious-txt": {
		Name:     "suspicious-txt",
		Client:   "127.0.0.6",
		Detects:  "txt_activity_anomaly",
		Summary:  "TXT used as a data channel, alongside the routine SPF/DKIM/DMARC lookups that must not be counted.",
		Duration: 6 * time.Minute,
		Build: func(r *rand.Rand) []query {
			var out []query
			at := time.Duration(0)
			for at < 6*time.Minute {
				// One in four is legitimate mail infrastructure, so the
				// scenario also demonstrates the exclusion working.
				if r.Intn(4) == 0 {
					out = append(out, query{
						at:    at,
						name:  "_dmarc.supplier.example",
						qtype: dns.TypeTXT,
					})
				} else {
					out = append(out, query{
						at:    at,
						name:  randomLabel(r, base32Alphabet, 32) + ".c2.example",
						qtype: dns.TypeTXT,
					})
				}
				at += time.Duration(1200+r.Intn(800)) * time.Millisecond
			}
			return out
		},
	},

	"dga-simulation": {
		Name:     "dga-simulation",
		Client:   "127.0.0.7",
		Detects:  "dga_like_domains",
		Summary:  "A generation algorithm walking its candidate list: many unrelated registered domains, random second-level labels, rotating TLDs, almost all failing.",
		Duration: 11 * time.Minute,
		Build: func(r *rand.Rand) []query {
			// Reserved TLDs only. A real DGA rotates .com/.net/.info; using
			// those here would mean querying names somebody could register.
			tlds := []string{"example", "test"}
			var out []query
			at := time.Duration(0)
			for at < 11*time.Minute {
				out = append(out, query{
					at: at,
					name: fmt.Sprintf("%s.%s",
						randomLabel(r, lowerAlphabet, 12+r.Intn(6)),
						tlds[r.Intn(len(tlds))]),
					qtype: dns.TypeA,
				})
				at += time.Duration(900+r.Intn(700)) * time.Millisecond
			}
			return out
		},
	},

	"beaconing": {
		Name:     "beaconing",
		Client:   "127.0.0.8",
		Detects:  "dns_beaconing_suspected",
		Summary:  "A fixed 45-second check-in with light jitter, for one name, sustained for half an hour.",
		Duration: 31 * time.Minute,
		Build: func(r *rand.Rand) []query {
			var out []query
			at := time.Duration(0)
			const period = 45 * time.Second
			for at < 31*time.Minute {
				out = append(out, query{
					at:    at,
					name:  "checkin.beacon.example",
					qtype: dns.TypeA,
				})
				// ±6% jitter: enough to look like a real implant, far too
				// little to look like a person.
				drift := time.Duration((r.Float64()*2 - 1) * 0.06 * float64(period))
				at += period + drift
			}
			return out
		},
	},
}

func scenarioNames() []string {
	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func listScenarios() {
	fmt.Println("DNS Daddy lab scenarios")
	fmt.Println()
	fmt.Println("All traffic uses .example and .test names (RFC 2606 / RFC 6761), which are")
	fmt.Println("reserved and not delegated. Nothing contacts real infrastructure.")
	fmt.Println()
	for _, n := range scenarioNames() {
		sc := scenarios[n]
		detects := sc.Detects
		if detects == "" {
			detects = "(nothing — this scenario shows the detectors staying quiet)"
		}
		fmt.Printf("  %-26s %s\n", n, sc.Summary)
		fmt.Printf("  %-26s client %s · %s · expects %s\n\n", "", sc.Client, sc.Duration, detects)
	}
	fmt.Println("Run one with:")
	fmt.Println("  dnsdaddy-lab -server 127.0.0.1:53 -scenario dns-tunnelling -speed 20")
}

// play sends a scenario's queries on its schedule.
func play(sc scenario, server, client string, seed int64, speed float64, dry, quiet bool) error {
	// A fixed seed per scenario name keeps scenarios independent: adding one
	// does not change the traffic any other scenario produces.
	r := rand.New(rand.NewSource(seed + int64(len(sc.Name)))) //nolint:gosec // synthetic traffic, not security-sensitive
	queries := sc.Build(r)

	fmt.Printf("▶ %s — %d queries over %s", sc.Name, len(queries), sc.Duration)
	if speed != 1 {
		fmt.Printf(" (replayed in ~%s)", (sc.Duration / time.Duration(speed)).Round(time.Second))
	}
	fmt.Println()
	if sc.Detects != "" {
		fmt.Printf("  expecting: %s\n", sc.Detects)
	} else {
		fmt.Printf("  expecting: no findings\n")
	}
	fmt.Printf("  client:    %s\n", client)

	if dry {
		for _, q := range queries {
			fmt.Printf("  %8s  %-6s %s\n", q.at.Round(time.Millisecond), dns.TypeToString[q.qtype], q.name)
		}
		return nil
	}

	conn, err := dialFrom(client, server)
	if err != nil {
		return err
	}
	defer conn.Close()

	start := time.Now()
	var sent, failed int

	for _, q := range queries {
		// Sleep until this query's slot in the compressed timeline.
		target := time.Duration(float64(q.at) / speed)
		if wait := target - time.Since(start); wait > 0 {
			time.Sleep(wait)
		}

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(q.name), q.qtype)
		m.RecursionDesired = true

		if err := send(conn, m); err != nil {
			failed++
			if !quiet && failed <= 3 {
				fmt.Printf("  ! %s: %v\n", q.name, err)
			}
			continue
		}
		sent++
		if !quiet && sent%50 == 0 {
			fmt.Printf("  … %d/%d\n", sent, len(queries))
		}
	}

	fmt.Printf("  done: %d sent", sent)
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	fmt.Printf(" in %s\n\n", time.Since(start).Round(time.Second))
	return nil
}

// dialFrom opens a UDP socket bound to a specific local address, so each
// scenario appears to the resolver as a distinct client.
func dialFrom(client, server string) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve server address: %w", err)
	}

	var laddr *net.UDPAddr
	if client != "" {
		laddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(client, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve client address: %w", err)
		}
	}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s from %s: %w (on non-Linux hosts only "+
			"127.0.0.1 is usually bound — pass -client 127.0.0.1)", server, client, err)
	}
	return conn, nil
}

// send writes one query and reads the reply, discarding it.
//
// The reply is read rather than ignored so the socket does not accumulate
// unread datagrams, and so a resolver that has stopped answering shows up as a
// timeout here rather than as silence. What the answer actually says does not
// matter: these names do not exist, and the point of the exercise is the
// question, not the answer.
func send(conn *net.UDPConn, m *dns.Msg) error {
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	if _, err := conn.Write(packed); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		// A timeout is not a failure worth stopping for: the lab cares that
		// the query was asked, and an upstream that cannot resolve a reserved
		// TLD quickly is entirely normal.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		return err
	}
	return nil
}
