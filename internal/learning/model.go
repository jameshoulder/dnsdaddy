package learning

import (
	"hash/maphash"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

type baseline struct {
	Windows  uint64                `json:"windows"`
	Queries  uint64                `json:"queries"`
	FirstAt  time.Time             `json:"firstAt"`
	LastAt   time.Time             `json:"lastAt"`
	Mean     [FeatureCount]float64 `json:"mean"`
	M2       [FeatureCount]float64 `json:"m2"`
	Variance [FeatureCount]float64 `json:"variance"`
}

func (b *baseline) ready(o Options) bool {
	return b.Windows >= uint64(o.WarmupWindows) && b.LastAt.Sub(b.FirstAt) >= o.WarmupDuration
}
func (b *baseline) train(v [FeatureCount]float64, w Window, o Options) {
	ready := b.ready(o)
	b.Windows++
	b.Queries += uint64(w.EligibleQueries)
	if b.FirstAt.IsZero() {
		b.FirstAt = w.Start
	}
	b.LastAt = w.End
	for i, x := range v {
		if !ready {
			// Welford's recurrence avoids cancellation when a quiet client
			// has many nearly identical windows.
			delta := x - b.Mean[i]
			b.Mean[i] += delta / float64(b.Windows)
			b.M2[i] += delta * (x - b.Mean[i])
			if b.Windows > 1 {
				b.Variance[i] = b.M2[i] / float64(b.Windows-1)
			}
			continue
		}
		// A window has one bounded vote, regardless of its query volume.
		// Clipping also limits the influence of a slowly changing attacker;
		// it cannot make an unsupervised baseline poisoning-proof.
		sd := math.Max(stdFloors[i], math.Sqrt(math.Max(0, b.Variance[i])))
		delta := math.Max(-2*sd, math.Min(2*sd, x-b.Mean[i]))
		b.Mean[i] += o.Alpha * delta
		b.Variance[i] = (1 - o.Alpha) * (b.Variance[i] + o.Alpha*delta*delta)
	}
}

type aggregate struct {
	Start           time.Time
	Count           int
	Eligible        int
	Blocked         int
	Errors          int
	SumLength       float64
	SumEntropy      float64
	SumLabels       float64
	TXT             int
	Unique          map[uint64]struct{}
	UniqueSaturated bool
	Overflow        bool
	Loss            bool
}
type clientState struct {
	Client      string    `json:"client"`
	NetworkID   string    `json:"networkId,omitempty"`
	Baseline    baseline  `json:"baseline"`
	LastSeen    time.Time `json:"lastSeen"`
	LastClosed  time.Time `json:"lastClosed"`
	LastFinding time.Time `json:"lastFinding"`
	window      *aggregate
}

// Model is a serial, deterministic state machine for offline evaluation and
// the asynchronous Engine. Its methods must not be used concurrently.
type Model struct {
	opts          Options
	clients       map[string]*clientState
	seed          maphash.Seed
	recent        []Result
	observations  ObservationCounts
	windows       WindowCounts
	evicted       uint64
	lastProcessed time.Time
	lossThrough   time.Time
}

func NewModel(o Options) (*Model, error) {
	o, err := o.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Model{opts: o, clients: make(map[string]*clientState), seed: maphash.MakeSeed(), recent: []Result{}}, nil
}

func clientKey(o detect.Observation) (string, bool) {
	if o.ClientIP != "" {
		ip, err := netip.ParseAddr(o.ClientIP)
		if err != nil {
			return "", false
		}
		return ip.Unmap().String(), true
	}
	if o.NetworkID != "" {
		if len(o.NetworkID) > 128 || strings.ContainsAny(o.NetworkID, "\r\n\x00") {
			return "", false
		}
		return "network:" + o.NetworkID, true
	}
	return "unattributed", true
}

// Observe scores only completed windows. Cached answers contribute to query
// behaviour; blocked and non-NOERROR responses contaminate a window and
// exclude that whole window from normal-baseline training.
func (m *Model) Observe(o detect.Observation) []Result {
	m.observations.Processed++
	key, valid := clientKey(o)
	if !valid || len(o.QName) > 254 || o.Time.IsZero() || len(o.NetworkID) > 128 || len(o.ClientName) > 256 || len(o.QType) > 10 || len(o.Rcode) > 16 {
		m.observations.Invalid++
		return nil
	}
	domain := domainutil.Normalize(o.QName)
	if domain == "" {
		m.observations.Invalid++
		return nil
	}
	at := o.Time.UTC()
	if at.After(m.lastProcessed) {
		m.lastProcessed = at
	}
	c := m.clients[key]
	if c != nil && !c.LastSeen.IsZero() && at.Sub(c.LastSeen) > m.opts.IdleTTL {
		if c.window != nil {
			m.windows.EvictedPending++
		}
		delete(m.clients, key)
		m.evicted++
		c = nil
	}
	if c == nil {
		if len(m.clients) >= m.opts.MaxClients {
			m.evictOldest()
		}
		c = &clientState{Client: key, NetworkID: o.NetworkID}
		m.clients[key] = c
	}
	start := at.Truncate(m.opts.Window)
	if (!c.LastClosed.IsZero() && start.Before(c.LastClosed)) || (c.window != nil && start.Before(c.window.Start)) {
		m.observations.Late++
		return nil
	}
	var out []Result
	if c.window != nil && start.After(c.window.Start) {
		out = append(out, m.complete(c))
	}
	if c.window == nil {
		c.window = &aggregate{Start: start, Unique: make(map[uint64]struct{})}
	}
	c.LastSeen = at
	a := c.window
	if a.Start.Before(m.lossThrough) {
		a.Loss = true
	}
	if a.Count >= m.opts.MaxWindowQueries {
		a.Overflow = true
		m.observations.WindowOverflow++
		return out
	}
	a.Count++
	if o.Blocked {
		a.Blocked++
		m.observations.Blocked++
		return out
	}
	if o.Rcode != "NOERROR" {
		a.Errors++
		m.observations.Errors++
		return out
	}
	a.Eligible++
	labels := strings.Split(domain, ".")
	maxLen := 0
	maxEntropy := 0.0
	for _, label := range labels {
		if len(label) > maxLen {
			maxLen = len(label)
		}
		if entropy := labelEntropy(label); entropy > maxEntropy {
			maxEntropy = entropy
		}
	}
	a.SumLength += float64(maxLen)
	a.SumEntropy += maxEntropy
	a.SumLabels += float64(len(labels))
	if o.QType == "TXT" {
		a.TXT++
	}
	hash := maphash.String(m.seed, domain)
	if _, exists := a.Unique[hash]; !exists {
		if len(a.Unique) < m.opts.MaxUniqueDomains {
			a.Unique[hash] = struct{}{}
		} else if !a.UniqueSaturated {
			a.UniqueSaturated = true
			m.observations.UniqueSaturated++
		}
	}
	return out
}

// MarkLoss prevents an incomplete sample from being treated as normal. The
// engine calls this for currently open windows after observation queue loss.
func (m *Model) MarkLoss() {
	m.lossThrough = time.Now().UTC().Truncate(m.opts.Window).Add(m.opts.Window)
	for _, c := range m.clients {
		if c.window != nil {
			c.window.Loss = true
		}
	}
}

// Advance closes elapsed windows; it does not invent zero-query windows.
func (m *Model) Advance(now time.Time) []Result {
	keys := make([]string, 0, len(m.clients))
	for key := range m.clients {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []Result
	for _, key := range keys {
		c := m.clients[key]
		if c.window != nil && !now.Before(c.window.Start.Add(m.opts.Window)) {
			out = append(out, m.complete(c))
		}
		if !c.LastSeen.IsZero() && now.Sub(c.LastSeen) > m.opts.IdleTTL {
			delete(m.clients, key)
			m.evicted++
		}
	}
	return out
}

func (m *Model) complete(c *clientState) Result {
	a := c.window
	c.window = nil
	c.LastClosed = a.Start.Add(m.opts.Window)
	r := Result{Client: c.Client, NetworkID: c.NetworkID, State: "insufficient", Window: Window{Start: a.Start, End: c.LastClosed, Queries: a.Count, EligibleQueries: a.Eligible}, Threshold: m.opts.Threshold, Features: []Feature{}, ExcludedReasons: []string{}, BaselineWindows: c.Baseline.Windows, BaselineQueries: c.Baseline.Queries}
	if !c.Baseline.FirstAt.IsZero() {
		r.BaselineAgeSeconds = int64(c.Baseline.LastAt.Sub(c.Baseline.FirstAt).Seconds())
	}
	m.windows.Completed++
	if a.Blocked > 0 {
		r.ExcludedReasons = append(r.ExcludedReasons, "policy_block_present")
	}
	if a.Errors > 0 {
		r.ExcludedReasons = append(r.ExcludedReasons, "non_success_response_present")
	}
	if a.Overflow {
		r.ExcludedReasons = append(r.ExcludedReasons, "window_query_limit")
	}
	if a.UniqueSaturated {
		r.ExcludedReasons = append(r.ExcludedReasons, "unique_domain_limit")
	}
	if a.Loss {
		r.ExcludedReasons = append(r.ExcludedReasons, "observation_queue_loss")
	}
	if a.Eligible < m.opts.MinWindowQueries {
		r.ExcludedReasons = append(r.ExcludedReasons, "too_few_successful_queries")
		m.windows.Insufficient++
		m.remember(r)
		return r
	}
	n := float64(a.Eligible)
	v := [FeatureCount]float64{math.Log1p(n / m.opts.Window.Minutes()), a.SumLength / n, a.SumEntropy / n, float64(len(a.Unique)) / n, float64(a.TXT) / n, a.SumLabels / n}
	ready := c.Baseline.ready(m.opts) && !a.Loss && !a.Overflow && !a.UniqueSaturated
	distance, maxZ := 0.0, 0.0
	for i, x := range v {
		f := Feature{Name: featureNames[i], Value: x}
		if ready {
			mean := c.Baseline.Mean[i]
			sd := math.Max(stdFloors[i], math.Sqrt(math.Max(0, c.Baseline.Variance[i])))
			z := math.Abs(x-mean) / sd
			f.BaselineMean = &mean
			f.BaselineStd = &sd
			f.Z = &z
			distance += math.Min(12, z) / FeatureCount
			maxZ = math.Max(maxZ, z)
			if z >= 3 {
				r.AnomalousSignals++
			}
		}
		r.Features = append(r.Features, f)
	}
	if ready {
		r.Score = &distance
		r.State = "typical"
	} else {
		r.State = "learning"
	}
	// This guard is intentionally conservative and visible. It prevents an
	// obvious encoded-name burst from defining normal during cold start; it
	// is not a malware classifier and can exclude legitimate CDN traffic.
	if (v[1] >= 40 && v[2] >= 3.8 && v[3] >= 0.75) || (v[4] >= 0.8 && v[1] >= 24) {
		r.ExcludedReasons = append(r.ExcludedReasons, "bootstrap_suspicious_shape")
	}
	if ready && distance >= m.opts.Threshold && r.AnomalousSignals >= 2 {
		r.State = "anomaly"
		m.windows.Anomalous++
		r.ExcludedReasons = append(r.ExcludedReasons, "anomalous_window")
	} else if ready && maxZ > 6 {
		r.ExcludedReasons = append(r.ExcludedReasons, "extreme_feature_quarantine")
	}
	if len(r.ExcludedReasons) == 0 {
		c.Baseline.train(v, r.Window, m.opts)
		r.Trained = true
		m.windows.Trained++
	} else {
		m.windows.Quarantined++
		if r.State != "anomaly" {
			r.State = "excluded"
		}
	}
	m.remember(r)
	return r
}

func (m *Model) remember(r Result) {
	if len(m.recent) == m.opts.RecentLimit {
		copy(m.recent, m.recent[1:])
		m.recent = m.recent[:len(m.recent)-1]
	}
	m.recent = append(m.recent, r)
}
func (m *Model) evictOldest() {
	var oldest *clientState
	for _, c := range m.clients {
		if oldest == nil || c.LastSeen.Before(oldest.LastSeen) || (c.LastSeen.Equal(oldest.LastSeen) && c.Client < oldest.Client) {
			oldest = c
		}
	}
	if oldest != nil {
		if oldest.window != nil {
			m.windows.EvictedPending++
		}
		delete(m.clients, oldest.Client)
		m.evicted++
	}
}
func labelEntropy(s string) float64 {
	var counts [256]uint8
	for i := range len(s) {
		counts[s[i]]++
	}
	out := 0.0
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(s))
			out -= p * math.Log2(p)
		}
	}
	return out
}

func (m *Model) Inspect(key string) (ClientView, bool) {
	c, ok := m.clients[key]
	if !ok {
		return ClientView{}, false
	}
	b := &c.Baseline
	v := ClientView{Client: key, NetworkID: c.NetworkID, Ready: b.ready(m.opts), BaselineWindows: b.Windows, BaselineQueries: b.Queries, FirstTrainedAt: b.FirstAt, LastTrainedAt: b.LastAt, LastSeenAt: c.LastSeen, Features: []Feature{}}
	if c.window != nil {
		v.PendingQueries = c.window.Count
	}
	for i, name := range featureNames {
		f := Feature{Name: name, Value: b.Mean[i]}
		if b.Windows > 0 {
			mean := b.Mean[i]
			sd := math.Max(stdFloors[i], math.Sqrt(math.Max(0, b.Variance[i])))
			f.BaselineMean = &mean
			f.BaselineStd = &sd
		}
		v.Features = append(v.Features, f)
	}
	return v, true
}

func (m *Model) Clients(limit int) []ClientView {
	if limit < 1 || limit > m.opts.MaxClients {
		limit = m.opts.MaxClients
	}
	states := make([]*clientState, 0, len(m.clients))
	for _, c := range m.clients {
		states = append(states, c)
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].LastSeen.Equal(states[j].LastSeen) {
			return states[i].Client < states[j].Client
		}
		return states[i].LastSeen.After(states[j].LastSeen)
	})
	if len(states) > limit {
		states = states[:limit]
	}
	out := make([]ClientView, 0, len(states))
	for _, c := range states {
		v, _ := m.Inspect(c.Client)
		out = append(out, v)
	}
	return out
}
