package store

import (
	"context"
	"strings"
	"time"
)

// This file holds the bounded reads behind the investigation view. Each one
// answers a question about one subject — a name or an address — over a
// stated window, from rows that already exist. Nothing here writes, and
// every query is bounded by the subject's own rows in the window rather than
// by the size of the log.

// ActivitySummary is what the query log recorded about one subject.
type ActivitySummary struct {
	// Queries is every recorded row for the subject in the window; the
	// three outcome counts sum to it.
	Queries int64 `json:"queries"`
	Allowed int64 `json:"allowed"`
	Blocked int64 `json:"blocked"`
	Errors  int64 `json:"errors"`
	// FirstSeen and LastSeen bound the subject's recorded activity in the
	// window. Nil when there is none.
	FirstSeen *time.Time `json:"firstSeen"`
	LastSeen  *time.Time `json:"lastSeen"`
	// QTypes counts questions by record type.
	QTypes map[string]int64 `json:"qtypes"`
	// Cached is how many allowed answers came from the answer cache.
	Cached int64 `json:"cached"`
	// AvgElapsedMS and MaxElapsedMS are over every recorded row, blocked
	// ones included; a blocked query's elapsed time is the policy's, not an
	// upstream's.
	AvgElapsedMS float64 `json:"avgElapsedMs"`
	MaxElapsedMS int64   `json:"maxElapsedMs"`
}

// ClientOfDomain is one client that asked for a name in the window.
type ClientOfDomain struct {
	ClientIP   string     `json:"clientIp"`
	ClientName string     `json:"clientName,omitempty"`
	NetworkID  string     `json:"networkId,omitempty"`
	Queries    int64      `json:"queries"`
	Blocked    int64      `json:"blocked"`
	LastSeen   *time.Time `json:"lastSeen"`
}

// DomainOfClient is one name a client asked for in the window.
type DomainOfClient struct {
	Domain  string `json:"domain"`
	Queries int64  `json:"queries"`
	Blocked int64  `json:"blocked"`
	// Category is the most recent recorded block category for this name,
	// or empty when nothing was blocked.
	Category string     `json:"category,omitempty"`
	LastSeen *time.Time `json:"lastSeen"`
}

// ActivitySummarySince aggregates one subject's rows in a window.
//
// Exactly one of domain and clientIP must be set; both narrows to the pair.
// One GROUP BY over the subject's rows, which the qname and client indexes
// bound to that subject rather than to the whole window.
func (s *Store) ActivitySummarySince(ctx context.Context, domain, clientIP string, since time.Time) (ActivitySummary, error) {
	return s.ActivitySummaryWindow(ctx, domain, clientIP, since, time.Time{})
}

// ActivitySummaryWindow uses the same fixed bounds as the investigation rows.
func (s *Store) ActivitySummaryWindow(ctx context.Context, domain, clientIP string, since, until time.Time) (ActivitySummary, error) {
	out := ActivitySummary{QTypes: map[string]int64{}}
	where, args := subjectPredicate(domain, clientIP, since, until)
	if where == "" {
		return out, nil
	}

	// #nosec G202 -- where is built from literal fragments by subjectPredicate;
	// every value is bound in args.
	rows, err := s.db.QueryContext(ctx, `
		SELECT action, qtype, COUNT(*), SUM(cached), MIN(ts), MAX(ts), AVG(elapsed_ms), MAX(elapsed_ms)
		  FROM query_log WHERE `+where+`
		 GROUP BY action, qtype`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	var (
		weightedElapsed float64
		first, last     int64
		haveAny         bool
	)
	for rows.Next() {
		var (
			action, qtype string
			n, cached     int64
			minTS, maxTS  int64
			avgMS         float64
			maxMS         int64
		)
		if err := rows.Scan(&action, &qtype, &n, &cached, &minTS, &maxTS, &avgMS, &maxMS); err != nil {
			return out, err
		}
		out.Queries += n
		switch action {
		case ActionAllowed:
			out.Allowed += n
			out.Cached += cached
		case ActionBlocked:
			out.Blocked += n
		case ActionError:
			out.Errors += n
		}
		out.QTypes[qtype] += n
		weightedElapsed += avgMS * float64(n)
		if maxMS > out.MaxElapsedMS {
			out.MaxElapsedMS = maxMS
		}
		if !haveAny || minTS < first {
			first = minTS
		}
		if !haveAny || maxTS > last {
			last = maxTS
		}
		haveAny = true
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if haveAny {
		f, l := fromUnixMilli(first), fromUnixMilli(last)
		out.FirstSeen, out.LastSeen = &f, &l
		out.AvgElapsedMS = weightedElapsed / float64(out.Queries)
	}
	return out, nil
}

// ClientsOfDomainSince lists which clients asked for a name in the window,
// busiest first, at most limit of them.
//
// Empty when client addresses are not recorded: the rows exist and carry no
// address, and this deliberately does not fall back to any other column to
// reconstruct one.
func (s *Store) ClientsOfDomainSince(ctx context.Context, domain string, since time.Time, limit int) ([]ClientOfDomain, error) {
	return s.ClientsOfDomainWindow(ctx, domain, since, time.Time{}, limit)
}

// ClientsOfDomainWindow returns one row per recorded client address. Names and
// network labels come from its newest in-window query, even after a rename or
// policy reassignment; those changes must not turn one address into two clients.
func (s *Store) ClientsOfDomainWindow(ctx context.Context, domain string, since, until time.Time, limit int) ([]ClientOfDomain, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where, args := subjectPredicate(domain, "", since, until)
	if where == "" {
		return []ClientOfDomain{}, nil
	}
	args = append(args, ActionBlocked, limit)
	// #nosec G202 -- subjectPredicate emits only literal predicates; values are bound.
	rows, err := s.db.QueryContext(ctx, `
		WITH activity AS (
			SELECT client_ip, client_name, network_id, action, ts,
			       ROW_NUMBER() OVER (PARTITION BY client_ip ORDER BY ts DESC, id DESC) AS newest
			  FROM query_log WHERE `+where+` AND client_ip <> ''
		)
		SELECT client_ip,
		       MAX(CASE WHEN newest = 1 THEN client_name END),
		       MAX(CASE WHEN newest = 1 THEN network_id END), COUNT(*),
		       SUM(CASE WHEN action = ? THEN 1 ELSE 0 END), MAX(ts)
		  FROM activity GROUP BY client_ip
		 ORDER BY COUNT(*) DESC, MAX(ts) DESC, client_ip ASC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientOfDomain{}
	for rows.Next() {
		var c ClientOfDomain
		var last int64
		if err := rows.Scan(&c.ClientIP, &c.ClientName, &c.NetworkID, &c.Queries, &c.Blocked, &last); err != nil {
			return nil, err
		}
		t := fromUnixMilli(last)
		c.LastSeen = &t
		out = append(out, c)
	}
	return out, rows.Err()
}

// DomainsOfClientSince lists what a client asked for in the window, most
// asked first, at most limit names.
func (s *Store) DomainsOfClientSince(ctx context.Context, clientIP string, since time.Time, limit int) ([]DomainOfClient, error) {
	return s.DomainsOfClientWindow(ctx, clientIP, since, time.Time{}, limit)
}

func (s *Store) DomainsOfClientWindow(ctx context.Context, clientIP string, since, until time.Time, limit int) ([]DomainOfClient, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	where, args := subjectPredicate("", clientIP, since, until)
	if where == "" {
		return []DomainOfClient{}, nil
	}
	args = append(args, ActionBlocked, ActionBlocked, limit)
	// #nosec G202 -- subjectPredicate emits only literal predicates; values are bound.
	rows, err := s.db.QueryContext(ctx, `
		WITH activity AS (
			SELECT qname, action, category, ts,
			       ROW_NUMBER() OVER (PARTITION BY qname, action ORDER BY ts DESC, id DESC) AS newest
			  FROM query_log WHERE `+where+`
		)
		SELECT qname, COUNT(*), SUM(CASE WHEN action = ? THEN 1 ELSE 0 END),
		       COALESCE(MAX(CASE WHEN action = ? AND newest = 1 THEN category END), ''), MAX(ts)
		  FROM activity GROUP BY qname
		 ORDER BY COUNT(*) DESC, MAX(ts) DESC, qname ASC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DomainOfClient{}
	for rows.Next() {
		var d DomainOfClient
		var last int64
		if err := rows.Scan(&d.Domain, &d.Queries, &d.Blocked, &d.Category, &last); err != nil {
			return nil, err
		}
		t := fromUnixMilli(last)
		d.LastSeen = &t
		out = append(out, d)
	}
	return out, rows.Err()
}

// subjectPredicate builds the WHERE clause for one subject in a window.
func subjectPredicate(domain, clientIP string, since, until time.Time) (string, []any) {
	var (
		parts []string
		args  []any
	)
	if domain != "" {
		parts = append(parts, "qname = ?")
		args = append(args, domain)
	}
	if clientIP != "" {
		parts = append(parts, "client_ip = ?")
		args = append(args, clientIP)
	}
	if len(parts) == 0 {
		return "", nil
	}
	parts = append(parts, "ts >= ?")
	args = append(args, unixMilli(since))
	if !until.IsZero() {
		parts = append(parts, "ts <= ?")
		args = append(args, unixMilli(until))
	}
	return strings.Join(parts, " AND "), args
}

// FindingsForDomainsSince returns findings whose recorded domain is any of
// the given names, newest first, at most limit.
//
// A finding records the registered domain it concerns while a query records
// the full name asked for, so the caller passes the name and each of its
// parent suffixes and this matches any of them exactly. Exactly, not by
// substring: "example.com" must not surface a finding about
// "notexample.com".
func (s *Store) FindingsForDomainsSince(ctx context.Context, domains []string, since time.Time, limit int) ([]Finding, bool, error) {
	return s.FindingsForDomains(ctx, domains, "", since, time.Time{}, limit)
}

// FindingsForDomains applies the client and window before LIMIT. Filtering a
// 50-row domain page afterward can hide every finding for a quieter client.
func (s *Store) FindingsForDomains(ctx context.Context, domains []string, client string, since, until time.Time, limit int) ([]Finding, bool, error) {
	if len(domains) == 0 {
		return []Finding{}, false, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(domains) > 64 {
		domains = domains[:64]
	}
	args := make([]any, 0, len(domains)+2)
	for _, d := range domains {
		args = append(args, d)
	}
	args = append(args, unixMilli(since))
	where := ""
	if client != "" {
		where += " AND client_ip = ?"
		args = append(args, client)
	}
	if !until.IsZero() {
		where += " AND ts <= ?"
		args = append(args, unixMilli(until))
	}
	args = append(args, limit+1)

	// #nosec G202 -- where is literal SQL; the other concatenation is a run of "?" built from
	// an integer count by placeholders(); every name is bound in args.
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, event_type, severity, confidence, score, client_ip, client_name,
		       network_id, domain, qtype, detector, title, summary, detail
		  FROM findings
		 WHERE domain IN (`+placeholders(len(domains))+`) AND ts >= ?`+where+`
		 ORDER BY ts DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]Finding, 0, limit)
	for rows.Next() {
		var (
			f  Finding
			ts int64
		)
		if err := rows.Scan(&f.ID, &ts, &f.EventType, &f.Severity, &f.Confidence, &f.Score,
			&f.ClientIP, &f.ClientName, &f.NetworkID, &f.Domain, &f.QType, &f.Detector,
			&f.Title, &f.Summary, &f.Detail); err != nil {
			return nil, false, err
		}
		f.Time = fromUnixMilli(ts)
		if len(out) == limit {
			return out, true, rows.Err()
		}
		out = append(out, f)
	}
	return out, false, rows.Err()
}

// EvidenceContributions counts, for each evidence row, the decisions it was
// cited as having decided.
//
// This is the difference between evidence that is on file and evidence that
// has changed an outcome, and an investigation view that showed the first as
// though it were the second would overstate every listing it displayed.
func (s *Store) EvidenceContributions(ctx context.Context, ids []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(ids) == 0 {
		return out, nil
	}
	const chunk = 200
	for start := 0; start < len(ids); start += chunk {
		end := min(start+chunk, len(ids))
		batch := ids[start:end]
		args := make([]any, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		// #nosec G202 -- placeholders() emits only "?" separated by commas;
		// every id is bound in args.
		rows, err := s.db.QueryContext(ctx, `
			SELECT evidence_id, COUNT(*) FROM decision_evidence
			 WHERE contributed = 1 AND evidence_id IN (`+placeholders(len(batch))+`)
			 GROUP BY evidence_id`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var n int64
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
