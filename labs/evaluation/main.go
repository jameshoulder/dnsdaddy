// Offline, reproducible evaluation of the experimental local learner.
// All names are reserved .example names. No network functions are imported.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/learning"
)

type record struct {
	Window   string    `json:"window"`
	Split    string    `json:"split"`
	Scenario string    `json:"scenario"`
	Label    string    `json:"label"`
	At       time.Time `json:"at"`
	Client   string    `json:"client"`
	Domain   string    `json:"domain"`
	QType    string    `json:"qtype"`
	Rcode    string    `json:"rcode"`
	Blocked  bool      `json:"blocked,omitempty"`
}

func (r record) observation() detect.Observation {
	return detect.Observation{Time: r.At, ClientIP: r.Client, NetworkID: "synthetic-evaluation", QName: r.Domain, QType: r.QType, Rcode: r.Rcode, Blocked: r.Blocked}
}

type spec struct {
	id, split, scenario, label, client, profile string
	at                                          time.Time
	count                                       int
	seed                                        int64
}
type window struct {
	id, label, scenario, client string
	at                          time.Time
	observations                []detect.Observation
}
type metric struct {
	Windows            int      `json:"windows"`
	Benign             int      `json:"benign"`
	Malicious          int      `json:"malicious"`
	Scored             int      `json:"scored"`
	AbstainedBenign    int      `json:"abstainedBenign"`
	AbstainedMalicious int      `json:"abstainedMalicious"`
	TP                 int      `json:"truePositive"`
	FP                 int      `json:"falsePositive"`
	TN                 int      `json:"trueNegative"`
	FN                 int      `json:"falseNegative"`
	RecallScored       *float64 `json:"recallAmongScoredMalicious"`
	DetectionFraction  *float64 `json:"detectionsDividedByAllMalicious"`
	FalseAlertFraction *float64 `json:"falseAlertsDividedByScoredBenign"`
	Precision          *float64 `json:"precision"`
}

func (m *metric) add(label string, scored, alert bool) {
	m.Windows++
	if label == "benign" {
		m.Benign++
	} else {
		m.Malicious++
	}
	if !scored {
		if label == "benign" {
			m.AbstainedBenign++
		} else {
			m.AbstainedMalicious++
		}
		return
	}
	m.Scored++
	if label == "benign" {
		if alert {
			m.FP++
		} else {
			m.TN++
		}
	} else if alert {
		m.TP++
	} else {
		m.FN++
	}
}
func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	x := float64(n) / float64(d)
	return &x
}
func (m *metric) finish() {
	m.RecallScored = ratio(m.TP, m.TP+m.FN)
	m.DetectionFraction = ratio(m.TP, m.Malicious)
	m.FalseAlertFraction = ratio(m.FP, m.FP+m.TN)
	m.Precision = ratio(m.TP, m.TP+m.FP)
}

type outcome struct {
	Window        string   `json:"window"`
	Scenario      string   `json:"scenario"`
	Label         string   `json:"label"`
	State         string   `json:"state"`
	Distance      *float64 `json:"distance"`
	Alert         bool     `json:"alert"`
	BaselineAlert bool     `json:"fixedRuleAlert"`
	Exclusions    []string `json:"exclusions"`
}
type report struct {
	Algorithm       string         `json:"algorithm"`
	DatasetVersion  int            `json:"datasetVersion"`
	TrainingWindows int            `json:"trainingWindows"`
	TrainingQueries int            `json:"trainingQueries"`
	TrainingEnd     time.Time      `json:"trainingEnd"`
	HeldOutStart    time.Time      `json:"heldOutStart"`
	HeldOutQueries  int            `json:"heldOutQueries"`
	ColdStart       metric         `json:"untrained"`
	Learned         metric         `json:"frozenLearnedModel"`
	FixedRule       metric         `json:"fixedLexicalRule"`
	Outcomes        []outcome      `json:"outcomes"`
	Drift           map[string]any `json:"gradualBenignShift"`
	Limitations     []string       `json:"limitations"`
}

func main() {
	dir := flag.String("dir", "labs/evaluation", "dataset/report directory")
	generate := flag.Bool("generate", false, "regenerate the checked-in deterministic synthetic dataset")
	flag.Parse()
	if err := run(*dir, *generate); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(dir string, generate bool) error {
	if generate {
		if err := generateFiles(dir); err != nil {
			return err
		}
	}
	training, err := readWindows(filepath.Join(dir, "data", "training.ndjson"), "train")
	if err != nil {
		return err
	}
	test, err := readWindows(filepath.Join(dir, "data", "heldout.ndjson"), "heldout")
	if err != nil {
		return err
	}
	m, _ := learning.NewModel(learning.Options{})
	cold, _ := learning.NewModel(learning.Options{})
	r := report{Algorithm: learning.Algorithm, DatasetVersion: 1, TrainingWindows: len(training), Outcomes: []outcome{}, Limitations: []string{
		"Synthetic, author-constructed windows, not independently collected production or malware-capture data.",
		"Labels express the generator's scenario intent; they are not investigated real-world outcomes.",
		"Default parameters were fixed before this held-out run, but the same author understands both model and generator: no independence claim.",
		"Only aggregate window shape is evaluated. Low-and-slow activity deliberately overlaps benign behaviour and may be missed.",
		"Failed/blocked traffic and clients without a prior baseline can abstain. Denominators include those abstentions explicitly.",
		"The fixed lexical comparator is a simple reference rule, not a benchmark of DNS Daddy's existing six detectors or another product.",
		"No real-world false-positive rate, maliciousness probability, block-safety claim or adversarial robustness guarantee follows from these results.",
	}}
	for _, w := range training {
		for _, o := range w.observations {
			m.Observe(o)
			r.TrainingQueries++
		}
		end := w.at.Add(5 * time.Minute)
		m.Advance(end)
		if end.After(r.TrainingEnd) {
			r.TrainingEnd = end
		}
	}
	for _, w := range test {
		if w.at.Before(r.TrainingEnd) {
			return fmt.Errorf("heldout window %s overlaps training", w.id)
		}
		if r.HeldOutStart.IsZero() || w.at.Before(r.HeldOutStart) {
			r.HeldOutStart = w.at
		}
		r.HeldOutQueries += len(w.observations)
		result, err := m.EvaluateWindow(w.observations)
		if err != nil {
			return fmt.Errorf("window %s: %w", w.id, err)
		}
		untrained, err := cold.EvaluateWindow(w.observations)
		if err != nil {
			return err
		}
		fixedScored, fixedAlert := lexicalRule(result)
		r.Learned.add(w.label, result.Score != nil, result.State == "anomaly")
		r.ColdStart.add(w.label, untrained.Score != nil, untrained.State == "anomaly")
		r.FixedRule.add(w.label, fixedScored, fixedAlert)
		r.Outcomes = append(r.Outcomes, outcome{Window: w.id, Scenario: w.scenario, Label: w.label, State: result.State, Distance: result.Score, Alert: result.State == "anomaly", BaselineAlert: fixedAlert, Exclusions: result.ExcludedReasons})
	}
	r.Learned.finish()
	r.ColdStart.finish()
	r.FixedRule.finish()
	r.Drift, err = driftExperiment(training, r.TrainingEnd)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "report.json"), r); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "RESULTS.md"), []byte(markdown(r)), 0644); err != nil {
		return err
	}
	fmt.Printf("Training: %d windows / %d queries. Held out: %d windows / %d queries.\n", r.TrainingWindows, r.TrainingQueries, r.Learned.Windows, r.HeldOutQueries)
	fmt.Printf("Learned: TP=%d FP=%d TN=%d FN=%d; abstained benign=%d malicious=%d. Cold-start scored=%d.\n", r.Learned.TP, r.Learned.FP, r.Learned.TN, r.Learned.FN, r.Learned.AbstainedBenign, r.Learned.AbstainedMalicious, r.ColdStart.Scored)
	return nil
}

func lexicalRule(r learning.Result) (bool, bool) {
	if len(r.Features) != learning.FeatureCount {
		return false, false
	}
	return true, r.Features[1].Value >= 28 && r.Features[2].Value >= 3.5
}
func driftExperiment(training []window, at time.Time) (map[string]any, error) {
	m, _ := learning.NewModel(learning.Options{})
	for _, w := range training {
		for _, o := range w.observations {
			m.Observe(o)
		}
		m.Advance(w.at.Add(5 * time.Minute))
	}
	before, _ := m.Inspect("192.0.2.10")
	accepted := 0
	var first, last *float64
	for i := range 24 {
		s := spec{id: "drift", client: "192.0.2.10", profile: "deployment", at: at.Add(time.Duration(i) * 5 * time.Minute), count: 60, seed: 9000 + int64(i)}
		obs := observations(s)
		scored, err := m.EvaluateWindow(obs)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			first = scored.Score
		}
		last = scored.Score
		for _, o := range obs {
			m.Observe(o)
		}
		for _, r := range m.Advance(s.at.Add(5 * time.Minute)) {
			if r.Trained {
				accepted++
			}
		}
	}
	after, _ := m.Inspect("192.0.2.10")
	return map[string]any{"experiment": "separate temporal benign-shift stream; not the frozen test set", "acceptedWindows": accepted, "distanceBeforeAdaptation": first, "distanceAfter23Updates": last, "meanLabelLengthBefore": before.Features[1].BaselineMean, "meanLabelLengthAfter": after.Features[1].BaselineMean}, nil
}

func datasetSpecs() []spec {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	profiles := []string{"web", "mail", "cdn", "telemetry"}
	clients := []string{"192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40"}
	out := []spec{}
	for i := range 24 {
		for j, profile := range profiles {
			out = append(out, spec{id: fmt.Sprintf("train-%s-%02d", profile, i), split: "train", scenario: profile, label: "benign", client: clients[j], profile: profile, at: base.Add(time.Duration(i) * 5 * time.Minute), count: 60, seed: 1000 + int64(i*7+j)})
		}
	}
	next := base.Add(3 * time.Hour)
	add := func(scenario, label, client, profile string, n int) {
		for i := range n {
			out = append(out, spec{id: fmt.Sprintf("test-%s-%02d", scenario, i), split: "heldout", scenario: scenario, label: label, client: client, profile: profile, at: next, count: 60, seed: 100000 + int64(len(out)*17)})
			next = next.Add(5 * time.Minute)
		}
	}
	for j, profile := range profiles {
		add("routine-"+profile, "benign", clients[j], profile, 6)
	}
	add("software-deployment", "benign", clients[0], "deployment", 6)
	add("new-legitimate-nonce-service", "benign", clients[0], "nonce", 4)
	add("new-client-routine", "benign", "192.0.2.200", "web", 4)
	add("encoded-txt-exfiltration", "malicious", clients[0], "exfil-txt", 4)
	add("encoded-address-exfiltration", "malicious", clients[2], "exfil-a", 4)
	add("mail-host-txt-channel", "malicious", clients[1], "exfil-txt", 4)
	add("dga-failed-resolution", "malicious", clients[0], "nxdomain", 4)
	add("low-and-slow-overlap", "malicious", clients[0], "web", 4)
	add("already-policy-blocked", "malicious", clients[0], "blocked", 4)
	add("new-client-exfiltration", "malicious", "192.0.2.201", "exfil-txt", 2)
	return out
}

func observations(s spec) []detect.Observation {
	rng := rand.New(rand.NewSource(s.seed))
	words := []string{"portal", "mail", "assets", "updates", "calendar", "login", "search", "storage"}
	out := make([]detect.Observation, 0, s.count)
	for i := range s.count {
		domain := words[rng.Intn(len(words))] + ".service.example"
		qtype := "A"
		if rng.Intn(4) == 0 {
			qtype = "AAAA"
		}
		rcode := "NOERROR"
		blocked := false
		switch s.profile {
		case "web":
			if i%23 == 0 {
				qtype = "TXT"
			}
		case "mail":
			patterns := []string{"_dmarc.mail%d.example", "selector1._domainkey.mail%d.example", "_spf.mail%d.example", "_mta-sts.mail%d.example"}
			domain = fmt.Sprintf(patterns[rng.Intn(len(patterns))], rng.Intn(8))
			qtype = "TXT"
		case "cdn":
			domain = randomLabel(rng, 28+rng.Intn(3), "abcdefghijklmnopqrstuvwxyz0123456789") + ".edge.cdn.example"
		case "telemetry":
			domain = randomLabel(rng, 32, "0123456789abcdef") + ".reputation.example"
		case "deployment":
			domain = fmt.Sprintf("workspace-%02d.service.example", i%8)
			if i%23 == 0 {
				qtype = "TXT"
			}
		case "nonce":
			domain = randomLabel(rng, 48, "abcdefghijklmnopqrstuvwxyz234567") + ".legitimate.example"
		case "exfil-txt":
			domain = randomLabel(rng, 52, "abcdefghijklmnopqrstuvwxyz234567") + ".transfer.example"
			qtype = "TXT"
		case "exfil-a":
			domain = randomLabel(rng, 60, "abcdefghijklmnopqrstuvwxyz234567") + ".remote.transfer.example"
		case "nxdomain":
			domain = randomLabel(rng, 20, "abcdefghijklmnopqrstuvwxyz") + ".candidate.example"
			rcode = "NXDOMAIN"
		case "blocked":
			domain = randomLabel(rng, 52, "abcdefghijklmnopqrstuvwxyz234567") + ".blocked.example"
			rcode = "NXDOMAIN"
			blocked = true
		}
		// Individual offsets vary while remaining inside a fixed five-minute
		// window; train and held-out nonce streams use disjoint PRNG seeds.
		offset := time.Duration(float64(i)*290/float64(s.count))*time.Second + time.Duration(rng.Intn(500))*time.Millisecond
		out = append(out, detect.Observation{Time: s.at.Add(offset), ClientIP: s.client, NetworkID: "synthetic-evaluation", QName: domain, QType: qtype, Rcode: rcode, Blocked: blocked})
	}
	return out
}
func randomLabel(rng *rand.Rand, n int, alphabet string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

func generateFiles(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0755); err != nil {
		return err
	}
	specs := datasetSpecs()
	checksums := map[string]string{}
	for _, split := range []string{"train", "heldout"} {
		rows := []record{}
		for _, s := range specs {
			if s.split != split {
				continue
			}
			for _, o := range observations(s) {
				rows = append(rows, record{Window: s.id, Split: s.split, Scenario: s.scenario, Label: s.label, At: o.Time, Client: o.ClientIP, Domain: o.QName, QType: o.QType, Rcode: o.Rcode, Blocked: o.Blocked})
			}
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].At.Equal(rows[j].At) {
				return rows[i].Window < rows[j].Window
			}
			return rows[i].At.Before(rows[j].At)
		})
		name := "heldout.ndjson"
		if split == "train" {
			name = "training.ndjson"
		}
		path := filepath.Join(dir, "data", name)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(f)
		for _, row := range rows {
			if err = encoder.Encode(row); err != nil {
				f.Close()
				return err
			}
		}
		if err = f.Close(); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		checksums[name] = hex.EncodeToString(sum[:])
	}
	return writeJSON(filepath.Join(dir, "data", "manifest.json"), map[string]any{"datasetVersion": 1, "source": "deterministic author-constructed synthetic traffic", "trainingSeeds": "1000 + window*7 + profile", "heldoutSeeds": "100000 + specification_index*17", "trainingWindows": 96, "reservedNames": ".example", "checksumsSha256": checksums, "windowSeconds": 300, "labels": "scenario intent, not independently investigated outcomes"})
}

func readWindows(path, split string) ([]window, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 65536)
	groups := map[string]*window{}
	for scanner.Scan() {
		var r record
		if err = json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return nil, err
		}
		if r.Split != split || (r.Label != "benign" && r.Label != "malicious") || !strings.HasSuffix(r.Domain, ".example") || r.At.IsZero() {
			return nil, fmt.Errorf("invalid or non-reserved dataset row")
		}
		w := groups[r.Window]
		if w == nil {
			w = &window{id: r.Window, label: r.Label, scenario: r.Scenario, client: r.Client, at: r.At.Truncate(5 * time.Minute)}
			groups[r.Window] = w
		}
		if r.Label != w.label || r.Client != w.client || r.Scenario != w.scenario || r.At.Truncate(5*time.Minute) != w.at {
			return nil, fmt.Errorf("inconsistent window metadata")
		}
		w.observations = append(w.observations, r.observation())
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	out := make([]window, 0, len(groups))
	for _, w := range groups {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].at.Equal(out[j].at) {
			return out[i].id < out[j].id
		}
		return out[i].at.Before(out[j].at)
	})
	return out, nil
}
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func number(p *float64) string {
	if p == nil {
		return "unavailable (zero denominator)"
	}
	return fmt.Sprintf("%.4f", *p)
}
func markdown(r report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Local learner: measured synthetic evaluation\n\nGenerated reproducibly by `go run ./labs/evaluation`. This is an offline engineering evaluation of `%s`. It does not estimate a production false-positive rate.\n\n", r.Algorithm)
	fmt.Fprintf(&b, "## Population and split\n\n- Training: **%d windows / %d queries** across four client profiles, ending %s.\n- Held out: **%d windows / %d queries**, starting %s: **%d benign**, **%d malicious-labelled** windows.\n- Windows span five minutes. Training labels are benign scenario intent. Held-out labels are used only for metric accounting.\n- The held-out model is frozen: each test window sees a copy of the prior baseline; it cannot update the baseline used by another test window.\n- Separate seeds are used for training and held-out traffic; the author wrote both the model and the generator, so this is not independent validation.\n\n", r.TrainingWindows, r.TrainingQueries, r.TrainingEnd.Format(time.RFC3339), r.Learned.Windows, r.HeldOutQueries, r.HeldOutStart.Format(time.RFC3339), r.Learned.Benign, r.Learned.Malicious)
	b.WriteString("## Outcomes with denominators\n\n| Model | Scored windows | TP | FP | TN | FN | Benign abstentions | Malicious abstentions |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, v := range []struct {
		name string
		m    metric
	}{{"Before any learning", r.ColdStart}, {"Frozen fitted baseline", r.Learned}, {"Fixed lexical reference rule", r.FixedRule}} {
		fmt.Fprintf(&b, "| %s | %d / %d | %d | %d | %d | %d | %d | %d |\n", v.name, v.m.Scored, v.m.Windows, v.m.TP, v.m.FP, v.m.TN, v.m.FN, v.m.AbstainedBenign, v.m.AbstainedMalicious)
	}
	fmt.Fprintf(&b, "\nFor the fitted model:\n\n- Recall among scored malicious-labelled windows: **%d / %d = %s**.\n- Detections divided by **all** malicious-labelled windows, including abstentions: **%d / %d = %s**.\n- False alerts divided by scored benign windows: **%d / %d = %s**.\n- Precision among emitted synthetic alerts: **%d / %d = %s**.\n\nAn abstention is not a correct benign classification. Before training, no score is fabricated. Failed resolution, already blocked traffic and new clients are visible coverage limitations.\n\n", r.Learned.TP, r.Learned.TP+r.Learned.FN, number(r.Learned.RecallScored), r.Learned.TP, r.Learned.Malicious, number(r.Learned.DetectionFraction), r.Learned.FP, r.Learned.FP+r.Learned.TN, number(r.Learned.FalseAlertFraction), r.Learned.TP, r.Learned.TP+r.Learned.FP, number(r.Learned.Precision))
	b.WriteString("The reference rule alerts when mean maximum label length is at least 28 characters and mean maximum label entropy is at least 3.5 bits. It has no fitted client history. It is intentionally simple and is **not** a comparison with the application's six existing heuristic detectors.\n\n## Scenario outcomes\n\n| Scenario | Label | Windows | Scores available | Alerts |\n|---|---|---:|---:|---:|\n")
	type tally struct {
		label            string
		n, scored, alert int
	}
	grouped := map[string]*tally{}
	names := []string{}
	for _, o := range r.Outcomes {
		t := grouped[o.Scenario]
		if t == nil {
			t = &tally{label: o.Label}
			grouped[o.Scenario] = t
			names = append(names, o.Scenario)
		}
		t.n++
		if o.Distance != nil {
			t.scored++
		}
		if o.Alert {
			t.alert++
		}
	}
	sort.Strings(names)
	for _, name := range names {
		t := grouped[name]
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d |\n", name, t.label, t.n, t.scored, t.alert)
	}
	b.WriteString("\n## Does the model actually adapt?\n\nA separate benign software-deployment stream is evaluated before each online update; it is not part of the frozen holdout.\n\n")
	drift, _ := json.MarshalIndent(r.Drift, "", "  ")
	fmt.Fprintf(&b, "```json\n%s\n```\n\n", drift)
	b.WriteString("## Limitations\n\n")
	for _, s := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	b.WriteString("\nThe deliberately overlapping low-and-slow scenario tests a limit of aggregate features. Legitimate new nonce traffic tests a plausible false alert. Review real findings and preserve the original evidence before considering future calibration; review labels do not automatically retrain this model.\n")
	return b.String()
}
