package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// doctorProbeName is the name the reachability probes ask for.
//
// Deliberately a name that must resolve and must never be on a blocklist:
// example.com is reserved by RFC 2606 for exactly this, so a block would be a
// bug in a feed rather than in the operator's configuration.
const doctorProbeName = "example.com."

// runDoctor diagnoses a deployment and returns a non-nil error when something
// is definitely wrong, so it can be used in a script.
//
// It reads configuration and the database, and sends real queries. It changes
// nothing: an operator running this is already having a bad day and must not
// have to wonder whether the diagnostic made it worse.
func runDoctor(args []string) error {
	fs := newFlagSet("doctor")
	configPath := fs.String("config", envOr("DNSDADDY_CONFIG", "/etc/dnsdaddy/config.yaml"), "path to the config file")
	asJSON := fs.Bool("json", false, "emit findings as JSON")
	timeout := fs.Duration("timeout", 5*time.Second, "per-probe timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var checks []diag.Check
	cfg, cfgChecks := doctorConfig(*configPath)
	checks = append(checks, cfgChecks...)
	checks = append(checks, doctorStorage(ctx, cfg)...)
	checks = append(checks, doctorListeners(ctx, cfg, *timeout)...)
	checks = append(checks, doctorClientAccess(ctx, cfg)...)
	checks = append(checks, doctorUpstreams(cfg, *timeout)...)
	checks = append(checks, doctorWeb(ctx, cfg, *timeout)...)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"version": version.String(),
			"status":  diag.Worst(checks),
			"checks":  checks,
		}); err != nil {
			return err
		}
	} else {
		renderDoctor(os.Stdout, checks)
	}

	if diag.Worst(checks) == diag.StatusFail {
		return errors.New("one or more checks failed")
	}
	return nil
}

// doctorConfig loads configuration, reporting rather than aborting when it
// cannot: every later check is still worth running against the defaults.
func doctorConfig(path string) (config.Config, []diag.Check) {
	c := diag.Check{Section: diag.SectionSystem, Name: "Configuration"}

	cfg, err := config.Load(path)
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The configuration could not be loaded, so DNS Daddy will not start."
		c.Evidence = []string{"config: " + path, "error: " + err.Error()}
		c.Action = "Correct the error above. A missing file is not a problem — defaults and " +
			"DNSDADDY_* environment variables are used — but a malformed one is."
		return config.Default(), []diag.Check{c}
	}

	c.Status = diag.StatusPass
	c.Summary = "Configuration loaded."
	c.Evidence = []string{"config: " + path, "data_dir: " + cfg.DataDir}
	if _, statErr := os.Stat(path); statErr != nil {
		c.Evidence = append(c.Evidence, "(no file at that path; using defaults and DNSDADDY_* variables)")
	}
	return cfg, []diag.Check{c}
}

// doctorStorage checks the data directory and the database.
func doctorStorage(ctx context.Context, cfg config.Config) []diag.Check {
	var checks []diag.Check

	dirCheck := diag.Check{Section: diag.SectionSystem, Name: "Data directory writable"}
	probe := filepath.Join(cfg.DataDir, ".dnsdaddy-doctor")
	switch f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); {
	case err != nil:
		dirCheck.Status = diag.StatusFail
		dirCheck.Summary = "The data directory is not writable, so nothing can be persisted."
		dirCheck.Evidence = []string{"data_dir: " + cfg.DataDir, "error: " + err.Error()}
		dirCheck.Action = "Check ownership and permissions. Under systemd the directory belongs to " +
			"the dnsdaddy user; under Docker it is the named volume."
	default:
		_ = f.Close()
		_ = os.Remove(probe)
		dirCheck.Status = diag.StatusPass
		dirCheck.Summary = "The data directory is writable."
		dirCheck.Evidence = []string{"data_dir: " + cfg.DataDir}
	}
	checks = append(checks, dirCheck)

	dbCheck := diag.Check{Section: diag.SectionDatabase, Name: "Database readable"}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		dbCheck.Status = diag.StatusFail
		dbCheck.Summary = "The database could not be opened."
		dbCheck.Evidence = []string{"path: " + cfg.DBPath(), "error: " + err.Error()}
		dbCheck.Action = "If DNS Daddy is running in a container, run this command inside it: " +
			"`docker compose exec dnsdaddy dnsdaddy doctor`."
		return append(checks, dbCheck)
	}
	defer st.Close()

	networks, err := st.ListNetworks(ctx)
	if err != nil {
		dbCheck.Status = diag.StatusFail
		dbCheck.Summary = "The database opened but could not be read."
		dbCheck.Evidence = []string{"error: " + err.Error()}
		return append(checks, dbCheck)
	}

	dbCheck.Status = diag.StatusPass
	dbCheck.Summary = fmt.Sprintf("Database readable, holding %d network(s).", len(networks))
	dbCheck.Evidence = []string{"path: " + cfg.DBPath()}
	return append(checks, dbCheck)
}

// doctorListeners establishes whether anything is serving DNS, and if not,
// what is in the way.
func doctorListeners(ctx context.Context, cfg config.Config, timeout time.Duration) []diag.Check {
	var checks []diag.Check

	for _, l := range []struct {
		addr  string
		proto string
	}{
		{cfg.DNS.ListenUDP, "udp"},
		{cfg.DNS.ListenTCP, "tcp"},
	} {
		if l.addr == "" {
			continue
		}
		target := probeTarget(l.addr)
		probe := queryResolver(ctx, l.proto, target, timeout)
		c := diag.ResolverReachability(probe, cfg.DNS.AllowedClientCIDRs)

		// Nothing answered. Distinguish "not running" from "something else has
		// the port", which are different problems with different remedies.
		if c.Status == diag.StatusFail && probe.Err != nil {
			bindable := portBindable(l.proto, l.addr)
			owners := listenersOn(l.proto, target)
			checks = append(checks, diag.PortConflict(l.proto, l.addr, bindable, owners))
			continue
		}
		checks = append(checks, c)
	}

	return checks
}

// doctorClientAccess is the configuration cross-check: which of the networks
// in the dashboard are actually permitted to send queries.
func doctorClientAccess(ctx context.Context, cfg config.Config) []diag.Check {
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		// doctorStorage has already reported this.
		return nil
	}
	defer st.Close()

	networks, err := st.ListNetworks(ctx)
	if err != nil {
		return nil
	}
	policies, err := st.ListPolicies(ctx)
	if err != nil {
		return nil
	}

	return diag.ClientAccess(diag.ClientAccessInput{
		AllowedCIDRs:        cfg.DNS.AllowedClientCIDRs,
		Networks:            diag.FromStoreNetworks(networks, diag.PolicyNames(policies)),
		AllowPublicResolver: cfg.DNS.AllowPublicResolver,
		// This process has served nothing; the live counter is on the running
		// daemon and reaches the operator through /metrics and the dashboard.
		RefusedQueries: -1,
	})
}

// doctorUpstreams tests each configured forwarder.
func doctorUpstreams(cfg config.Config, timeout time.Duration) []diag.Check {
	probes := make([]diag.UpstreamProbe, 0, len(cfg.DNS.Upstreams))
	for _, spec := range cfg.DNS.Upstreams {
		probes = append(probes, probeUpstream(spec, timeout))
	}
	return diag.Upstreams(probes)
}

// doctorWeb checks the dashboard and reads the live threat-index size from it.
func doctorWeb(ctx context.Context, cfg config.Config, timeout time.Duration) []diag.Check {
	target := probeTarget(cfg.HTTP.Listen)
	url := "http://" + target + "/api/v1/health"

	c := diag.Check{Section: diag.SectionWeb, Name: "Dashboard responding"}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The dashboard address could not be used."
		c.Evidence = []string{"listen: " + cfg.HTTP.Listen, "error: " + err.Error()}
		return []diag.Check{c}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The dashboard did not respond."
		c.Evidence = []string{"url: " + url, "error: " + err.Error()}
		c.Action = "If DNS Daddy runs in a container, the dashboard is published on loopback only " +
			"and this must be run inside the container: " +
			"`docker compose exec dnsdaddy dnsdaddy doctor`."
		return []diag.Check{c}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		c.Status = diag.StatusFail
		c.Summary = fmt.Sprintf("The dashboard answered HTTP %d.", resp.StatusCode)
		c.Evidence = []string{"url: " + url}
		return []diag.Check{c}
	}

	var health struct {
		Status        string `json:"status"`
		BlocklistSize int    `json:"blocklistSize"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		c.Status = diag.StatusWarn
		c.Summary = "The dashboard responded, but the health payload was not readable."
		c.Evidence = []string{"url: " + url}
		return []diag.Check{c}
	}

	c.Status = diag.StatusPass
	c.Summary = "The dashboard and management API are responding."
	c.Evidence = []string{"url: " + url, "status: " + health.Status}

	// The running process owns the live index, so its size is only knowable
	// from the API. Feed timestamps come from the database.
	return []diag.Check{c, doctorIntel(ctx, cfg, health.BlocklistSize)}
}

// doctorIntel reports whether filtering is actually in force.
func doctorIntel(ctx context.Context, cfg config.Config, indexed int) diag.Check {
	var last time.Time

	if st, err := store.Open(cfg.DBPath()); err == nil {
		defer st.Close()
		if feeds, err := st.ListFeeds(ctx); err == nil {
			// LastSuccess, not LastRefresh. A feed that has errored since
			// Tuesday has a refresh timestamp of a minute ago and
			// intelligence three days old; reporting the former would call
			// stale data fresh, which is the exact failure this section
			// exists to catch.
			for _, f := range feeds {
				if f.Enabled && f.LastSuccess != nil && f.LastSuccess.After(last) {
					last = *f.LastSuccess
				}
			}
		}
	}

	// Twice the shipped refresh interval: one missed refresh is a hiccup, two
	// is a pattern worth mentioning.
	staleAfter := 2 * cfg.Feeds.RefreshInterval.D()
	if staleAfter <= 0 {
		staleAfter = 48 * time.Hour
	}
	return diag.ThreatIndex(indexed, last, time.Now(), staleAfter)
}

// --- probes -----------------------------------------------------------------

// queryResolver sends a real DNS question at addr, which is the only way to
// establish that the resolver serves this client rather than merely that a
// socket is open.
func queryResolver(ctx context.Context, proto, addr string, timeout time.Duration) diag.ResolverProbe {
	p := diag.ResolverProbe{Address: addr, Proto: proto}

	m := new(dns.Msg)
	m.SetQuestion(doctorProbeName, dns.TypeA)
	m.RecursionDesired = true

	client := &dns.Client{Net: proto, Timeout: timeout}
	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, m, addr)
	p.Elapsed = time.Since(start)

	if err != nil {
		p.Err = err
		return p
	}
	p.Rcode = dns.RcodeToString[resp.Rcode]
	p.SourceAddr = localAddrTowards(proto, addr)
	return p
}

// probeUpstream opens a connection to a configured forwarder.
//
// It dials rather than resolving: the question is whether this machine can
// reach the address at all, and a full exchange over DNS-over-TLS would
// conflate a blocked port with a certificate problem.
func probeUpstream(spec string, timeout time.Duration) diag.UpstreamProbe {
	p := diag.UpstreamProbe{Spec: spec}

	network, host := upstreamDialTarget(spec)
	start := time.Now()
	conn, err := net.DialTimeout(network, host, timeout)
	p.Elapsed = time.Since(start)
	if err != nil {
		p.Err = err
		return p
	}
	_ = conn.Close()
	return p
}

// upstreamDialTarget reduces an upstream spec to something net.Dial accepts.
func upstreamDialTarget(spec string) (network, address string) {
	// Strip the "#hostname" TLS verification suffix, which is not part of the
	// address.
	if i := strings.Index(spec, "#"); i >= 0 {
		spec = spec[:i]
	}

	network = "udp"
	defaultPort := "53"
	switch {
	case strings.HasPrefix(spec, "tls://"):
		spec, network, defaultPort = strings.TrimPrefix(spec, "tls://"), "tcp", "853"
	case strings.HasPrefix(spec, "https://"):
		spec, network, defaultPort = strings.TrimPrefix(spec, "https://"), "tcp", "443"
		if i := strings.Index(spec, "/"); i >= 0 {
			spec = spec[:i]
		}
	case strings.HasPrefix(spec, "tcp://"):
		spec, network = strings.TrimPrefix(spec, "tcp://"), "tcp"
	case strings.HasPrefix(spec, "udp://"):
		spec = strings.TrimPrefix(spec, "udp://")
	}

	if _, _, err := net.SplitHostPort(spec); err != nil {
		spec = net.JoinHostPort(spec, defaultPort)
	}
	return network, spec
}

// probeTarget turns a listen address into one a client can connect to.
// ":53" and "0.0.0.0:53" mean "every interface", which is not an address you
// can send to; loopback is the reachable member of that set.
func probeTarget(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// portBindable reports whether the port is free, which distinguishes "DNS
// Daddy is not running" from "something else holds the port".
func portBindable(proto, addr string) bool {
	switch proto {
	case "udp":
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	default:
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		_ = l.Close()
		return true
	}
}

// localAddrTowards reports the source address this machine would use to reach
// addr. That is the address the resolver judges against its ACL, and knowing
// it is the difference between a guess and a diagnosis.
func localAddrTowards(proto, addr string) string {
	network := "udp"
	if proto == "tcp" {
		network = "tcp"
	}
	conn, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

// --- rendering --------------------------------------------------------------

func renderDoctor(w io.Writer, checks []diag.Check) {
	fmt.Fprintf(w, "DNS Daddy doctor — %s\n", version.String())

	section := ""
	for _, c := range checks {
		if c.Section != section {
			section = c.Section
			fmt.Fprintf(w, "\n%s\n", section)
		}
		fmt.Fprintf(w, "  [%s] %s\n", strings.ToUpper(string(c.Status)), c.Summary)
		for _, e := range c.Evidence {
			fmt.Fprintf(w, "         %s\n", e)
		}
		if c.Action != "" && c.Status != diag.StatusPass {
			for i, line := range wrap(c.Action, 68) {
				prefix := "         → "
				if i > 0 {
					prefix = "           "
				}
				fmt.Fprintf(w, "%s%s\n", prefix, line)
			}
		}
	}

	fmt.Fprintln(w)
	switch diag.Worst(checks) {
	case diag.StatusFail:
		fmt.Fprintln(w, "NOT READY — see the FAIL lines above.")
	case diag.StatusWarn:
		fmt.Fprintln(w, "READY, with warnings.")
	default:
		fmt.Fprintln(w, "READY")
	}
}

// wrap breaks text on spaces at width columns, so an action reads as prose in
// a terminal rather than as one very long line.
func wrap(s string, width int) []string {
	var (
		lines []string
		line  string
	)
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
