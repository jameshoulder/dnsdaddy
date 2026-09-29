package dnssec

import (
	"context"

	"github.com/miekg/dns"
)

// ValidateQuestions authenticates a bounded collection of questions as one
// operation. The caller must bind each question to the exact records it will
// serve, rather than fetch a replacement answer while validating it.
//
// A single lookup and NSEC3 hash budget covers the entire collection. This is
// used by the native client path: an unsigned alias must not hide a bogus
// signed target, and an AD response must authenticate every RRset it serves.
// Each question retains its own result and trace; the consumer combines them
// by the weakest status, never by the most recent one.
func (v *Validator) ValidateQuestions(ctx context.Context, questions []dns.Question) []ValidationResult {
	if len(questions) == 0 {
		return nil
	}
	w := v.newWalk(ctx, dns.CanonicalName(questions[0].Name), questions[0].Qtype, v.cfg.Clock.Now())
	limit := v.cfg.Limits.MaxAnyRRsets
	if len(questions) > limit {
		return []ValidationResult{w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepLimit, Note: "too many RRsets in one client response"}, ReasonResourceLimit,
		))}
	}
	out := make([]ValidationResult, 0, len(questions))
	for _, q := range questions {
		name := dns.CanonicalName(q.Name)
		w.rec = newRecorder(name, q.Qtype, w.now)
		out = append(out, w.chase(name, q.Qtype))
	}
	return out
}
