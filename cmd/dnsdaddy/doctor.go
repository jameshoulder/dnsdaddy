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
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
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
	checks = append(checks, doctorDataDir(cfg))

	// One read-only handle, shared by every check that needs it. See
	// openExistingStore for why it is not store.Open: this command promises to
	// change nothing, and that promise has to hold against an older
	// deployment's database as well as a missing one.
	st, dbCheck := openExistingStore(ctx, cfg)
	if st != nil {
		defer st.Close()
	}

	// The effective ACL, computed once: the same union of configuration and
	// dashboard permissions the daemon admits on. Every check that quotes "who
	// may resolve" quotes this, so the listener probe and the client-access
	// section cannot disagree with each other or with the running resolver.
	acl := doctorACL(ctx, st, cfg)

	// Asked first, rendered last. The dashboard is the only place a failed
	// client-access reload is visible — it lives in the running daemon's
	// memory, and this process rebuilds the ACL from configuration and the
	// database, which is what *should* be enforced rather than what is.
	webChecks, aclStale := doctorWeb(ctx, st, cfg, *timeout)

	checks = append(checks, dbCheck)
	checks = append(checks, doctorListeners(ctx, cfg, acl, *timeout)...)
	checks = append(checks, doctorClientAccess(ctx, st, cfg, acl, aclStale)...)
	checks = append(checks, doctorUpstreams(cfg, *timeout)...)
	checks = append(checks, webChecks...)

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

// doctorDataDir checks that persistence has somewhere to go.
func doctorDataDir(cfg config.Config) diag.Check {
	c := diag.Check{Section: diag.SectionSystem, Name: "Data directory writable"}

	probe := filepath.Join(cfg.DataDir, ".dnsdaddy-doctor")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- path built from the operator's own data_dir
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The data directory is not writable, so nothing can be persisted."
		c.Evidence = []string{"data_dir: " + cfg.DataDir, "error: " + err.Error()}
		c.Action = "Check ownership and permissions. Under systemd the directory belongs to " +
			"the dnsdaddy user; under Docker it is the named volume."
		return c
	}
	_ = f.Close()
	_ = os.Remove(probe)

	c.Status = diag.StatusPass
	c.Summary = "The data directory is writable."
	c.Evidence = []string{"data_dir: " + cfg.DataDir}
	return c
}

// openExistingStore opens the database for inspection, without changing it.
//
// store.OpenReadOnly, not store.Open. Open is right for the daemon that owns
// the database and wrong here: it applies the schema, runs migrations, seeds
// defaults and switches journalling to WAL, so a newer binary's doctor run
// against an older live deployment would have migrated it — a modification
// made by the one command that promises to make none. It also creates a
// missing file, so a mistyped data_dir was answered with a manufactured empty
// database rather than with the truth.
//
// A nil store is returned when there is nothing to open, and every caller
// tolerates it.
func openExistingStore(ctx context.Context, cfg config.Config) (*store.Store, diag.Check) {
	c := diag.Check{Section: diag.SectionDatabase, Name: "Database readable"}
	path := cfg.DBPath()

	if _, err := os.Stat(path); err != nil {
		c.Status = diag.StatusFail
		c.Summary = "There is no database at the configured path."
		c.Evidence = []string{"path: " + path}
		c.Action = "On a first run this is expected until DNS Daddy has started once. Otherwise " +
			"data_dir points somewhere other than the running instance — under Docker the " +
			"database lives in a volume, so run `docker compose exec dnsdaddy dnsdaddy doctor`."
		return nil, c
	}

	st, err := store.OpenReadOnly(path)
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The database exists but could not be opened for reading."
		c.Evidence = []string{"path: " + path, "error: " + err.Error()}
		c.Action = "Check that this user can read the file. Under systemd the database belongs " +
			"to the dnsdaddy user, so this normally wants sudo."
		return nil, c
	}

	networks, err := st.ListNetworks(ctx)
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The database opened but could not be read."
		c.Evidence = []string{"path: " + path, "error: " + err.Error()}
		// The likely cause of "no such column" is a half-finished upgrade:
		// this binary is newer than the one that last opened the database, and
		// nothing has applied the migration yet because doctor deliberately
		// does not write. Saying so is more use than the raw SQLite error.
		if strings.Contains(err.Error(), "no such column") {
			c.Action = "This database was last written by an older DNS Daddy than this binary, and " +
				"doctor will not migrate it — it changes nothing by design. Start the resolver " +
				"once (`docker compose up -d`, or `systemctl start dnsdaddy`), which applies the " +
				"migration, then run this again."
		}
		return st, c
	}

	c.Status = diag.StatusPass
	c.Summary = fmt.Sprintf("Database readable, holding %d network(s).", len(networks))
	c.Evidence = []string{"path: " + path}
	return st, c
}

// doctorListeners establishes whether anything is serving DNS, and if not,
// what is in the way.
func doctorListeners(ctx context.Context, cfg config.Config, acl *clientacl.Set, timeout time.Duration) []diag.Check {
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
		c := diag.ResolverReachability(probe, acl.Effective())

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

// doctorClientAccess is the cross-check that answers the question an operator
// actually has: who may use this resolver, and does that include the networks
// they configured?
//
// It computes the same effective ACL the daemon runs on — the bootstrap list
// from configuration unioned with the dashboard's permissions — rather than
// reporting either source alone. Reporting configuration alone was the old
// behaviour and would now be worse than useless: it would tell an operator
// their network was refused by a resolver that is serving it.
func doctorClientAccess(ctx context.Context, st *store.Store, cfg config.Config, acl *clientacl.Set, stale bool) []diag.Check {
	in := diag.ClientAccessInput{
		ACL:   acl,
		Stale: stale,
		// This process has served nothing; the live counter is on the running
		// daemon and reaches the operator through /metrics and the dashboard.
		RefusedQueries: nil,
	}
	if st == nil {
		return diag.ClientAccess(in)
	}

	networks, err := st.ListNetworks(ctx)
	if err != nil {
		return diag.ClientAccess(in)
	}
	policies, err := st.ListPolicies(ctx)
	if err != nil {
		return diag.ClientAccess(in)
	}
	in.Networks = diag.FromStoreNetworks(networks, diag.PolicyNames(policies))
	return diag.ClientAccess(in)
}

// doctorACL rebuilds the effective client ACL from configuration and the
// database.
//
// Without a readable database only the bootstrap half is knowable. That is
// reported honestly — the summary names its source — rather than being
// presented as the whole answer, because a doctor that quietly reports half an
// ACL is how an operator concludes their permission did not save.
func doctorACL(ctx context.Context, st *store.Store, cfg config.Config) *clientacl.Set {
	var networks []clientacl.Network
	if st != nil {
		if stored, err := st.ListNetworks(ctx); err == nil {
			networks = store.ClientACLNetworks(stored)
		}
	}
	return clientacl.Compute(cfg.DNS.AllowedClientCIDRs, cfg.DNS.AllowPublicResolver, networks)
}

// doctorUpstreams tests each configured forwarder.
func doctorUpstreams(cfg config.Config, timeout time.Duration) []diag.Check {
	probes := make([]diag.UpstreamProbe, 0, len(cfg.DNS.Upstreams))
	for _, spec := range cfg.DNS.Upstreams {
		probes = append(probes, probeUpstream(spec, timeout))
	}
	return diag.Upstreams(probes)
}

// doctorWeb checks the dashboard, and reads from it the two things only the
// running process knows: the size of the live threat index, and whether a
// client-access reload has failed.
//
// It returns the stale flag separately because the CLIENT ACCESS section is
// rendered before this one and needs the answer. Everything else doctor
// reports is derived from configuration and the database, which is the
// *desired* state; these two are the enforced one.
func doctorWeb(ctx context.Context, st *store.Store, cfg config.Config, timeout time.Duration) ([]diag.Check, bool) {
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
		return []diag.Check{c, intelUnknown()}, false
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.Status = diag.StatusFail
		c.Summary = "The dashboard did not respond."
		c.Evidence = []string{"url: " + url, "error: " + err.Error()}
		c.Action = "If DNS Daddy runs in a container, the dashboard is published on loopback only " +
			"and this must be run inside the container: " +
			"`docker compose exec dnsdaddy dnsdaddy doctor`."
		return []diag.Check{c, intelUnknown()}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		c.Status = diag.StatusFail
		c.Summary = fmt.Sprintf("The dashboard answered HTTP %d.", resp.StatusCode)
		c.Evidence = []string{"url: " + url}
		return []diag.Check{c, intelUnknown()}, false
	}

	var health struct {
		Status         string `json:"status"`
		BlocklistSize  int    `json:"blocklistSize"`
		ClientACLStale bool   `json:"clientAclStale"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		c.Status = diag.StatusWarn
		c.Summary = "The dashboard responded, but the health payload was not readable."
		c.Evidence = []string{"url: " + url}
		return []diag.Check{c, intelUnknown()}, false
	}

	c.Status = diag.StatusPass
	c.Summary = "The dashboard and management API are responding."
	c.Evidence = []string{"url: " + url, "status: " + health.Status}

	// The running process owns the live index, so its size is only knowable
	// from the API. Feed timestamps come from the database.
	return []diag.Check{c, doctorIntel(ctx, st, cfg, health.BlocklistSize)}, health.ClientACLStale
}

// doctorIntel reports whether filtering is actually in force.
func doctorIntel(ctx context.Context, st *store.Store, cfg config.Config, indexed int) diag.Check {
	var last time.Time

	if st != nil {
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

// intelUnknown stands in when the live index size could not be read.
//
// The index belongs to the running process, so only its API can report it.
// Omitting the section when the API is unreachable would leave the reader to
// infer that filtering was checked and found fine, which is the misleading
// green this whole command exists to remove.
func intelUnknown() diag.Check {
	return diag.Check{
		Section: diag.SectionIntel,
		Name:    "Threat index loaded",
		Status:  diag.StatusWarn,
		Summary: "Whether filtering is in force could not be determined.",
		Action: "The live index is only readable from the running process, and its API did not " +
			"answer — see the WEB INTERFACE check above.",
	}
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

// probeUpstream sends a real DNS question through a configured forwarder.
//
// It goes through resolver.ParseUpstream and Upstream.Exchange — the same
// transport the resolver itself uses — rather than a second client stack of
// its own. That is what makes the answer mean anything: a UDP "connection" is
// only a local socket association, so net.Dial succeeds without a packet
// leaving the machine and a silent or absent resolver looks reachable. A TCP
// accept proves a socket opened, not that DNS is spoken over it, and it says
// nothing at all about whether a DoT certificate verifies or a DoH endpoint
// serves anything.
//
// Using the resolver's own transport also means DoT verification, the DoH
// request shape, and the truncation retry are exercised exactly as they are in
// production, and cannot drift away from it.
func probeUpstream(spec string, timeout time.Duration) diag.UpstreamProbe {
	p := diag.UpstreamProbe{Spec: spec}

	u, err := resolver.ParseUpstream(spec, timeout)
	if err != nil {
		p.Err = err
		return p
	}
	defer u.Close()

	m := new(dns.Msg)
	m.SetQuestion(doctorProbeName, dns.TypeA)
	m.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	resp, err := u.Exchange(ctx, m)
	p.Elapsed = time.Since(start)

	switch {
	case err != nil:
		p.Err = err
	case resp == nil:
		p.Err = errors.New("upstream returned no message")
	case !answersQuestion(resp, m.Question[0]):
		// miekg/dns matches the transaction ID; the question is ours to check.
		// Something answering with a different question is not serving us.
		p.Err = errors.New("upstream answered a different question")
	default:
		p.Rcode = rcodeName(resp.Rcode)
	}
	return p
}

// rcodeName never returns an empty string. dns.RcodeToString has no entry for
// a code it does not know, and an empty rcode rendered into a finding reads as
// a bug in the diagnostic rather than as news about the upstream.
func rcodeName(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// answersQuestion reports whether resp addresses the question we asked.
func answersQuestion(resp *dns.Msg, q dns.Question) bool {
	if len(resp.Question) != 1 {
		return false
	}
	got := resp.Question[0]
	return strings.EqualFold(got.Name, q.Name) && got.Qtype == q.Qtype && got.Qclass == q.Qclass
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
