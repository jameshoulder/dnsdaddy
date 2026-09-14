package diag

import "fmt"

// ListingDatesInput describes whether this installation can say how long a
// feed has been listing something.
type ListingDatesInput struct {
	// Available reports that the table could be read at all.
	Available bool
	// Live is how many current listings have dates; History is how many
	// dropped ones are kept.
	Live    int64
	History int64
	// Feeds is how many feeds have contributed dates.
	Feeds int64
	// MaxRows is the ceiling. Zero means no ceiling.
	MaxRows int
	// RecordingFailures counts blocklist rebuilds that could not record dates.
	// Non-zero means the dates are stale, not that blocking is affected.
	RecordingFailures uint64
	// RetentionDays is how long dropped listings are kept.
	RetentionDays int
}

// nearlyFullFraction is when the table is worth mentioning.
//
// Eighty per cent, the same point the first-seen index warns at, and for the
// same reason: past the ceiling new listings stop getting dates, and an
// operator would rather hear about that before the dates start going missing
// than afterwards.
const nearlyFullFraction = 0.8

// ListingDates reports whether DNS Daddy knows how long its feeds have been
// listing what they list.
//
// Never a failure on an empty table. A fresh install has recorded nothing
// because no feed has refreshed yet, and reporting that as a fault would teach
// an operator to ignore this check within a day.
func ListingDates(in ListingDatesInput) []Check {
	c := Check{Section: SectionIntel, Name: "Listing dates"}

	total := in.Live + in.History
	switch {
	case !in.Available:
		// The table could not be read. That is a schema or database fault
		// rather than a setting, and it is the only thing here that is a
		// failure — everything else is a shortage of history, which costs an
		// explanation rather than any protection.
		c.Status = StatusFail
		c.Summary = "The record of when feeds listed each domain could not be read."
		c.Action = "This is a database fault rather than a setting. Check the startup " +
			"log and please report it."

	case in.RecordingFailures > 0:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("Listing dates are out of date: %d blocklist update(s) "+
			"could not record them.", in.RecordingFailures)
		c.Evidence = []string{
			"blocking is unaffected — it is built from the feeds, not from these dates",
			fmt.Sprintf("%d current listing(s) have dates", in.Live),
		}
		c.Action = "Check that the database is writable and has free space."

	case total == 0:
		// Correct on a fresh install, and said plainly so nobody goes looking
		// for a fault.
		c.Status = StatusWarn
		c.Summary = "No listing dates recorded yet."
		c.Evidence = []string{
			"they are written when feeds refresh, so this is normal on a new installation",
			"until then, a block is explained without saying how long the feed has listed it",
		}
		c.Action = "Nothing to do. Dates appear after the first feed update."

	case in.MaxRows > 0 && float64(total) >= float64(in.MaxRows)*nearlyFullFraction:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("The listing-date record is %d%% full: %s of %s rows.",
			int(float64(total)/float64(in.MaxRows)*100), thousandsSep(total), thousandsSep(int64(in.MaxRows)))
		c.Evidence = []string{
			"past the ceiling, domains that feeds start listing get no dates",
			"dates for what feeds list right now are never discarded to make room — " +
				"history for dropped domains goes first",
		}
		c.Action = "Expected if you have added large feeds. Shorten how long dropped " +
			"listings are kept, or use a machine with a larger size."

	default:
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("%s current listing(s) across %d feed(s) have dates.",
			thousandsSep(in.Live), in.Feeds)
		ev := []string{
			"a domain a feed keeps listing keeps its original first-seen date, " +
				"across every update",
		}
		if in.History > 0 {
			ev = append(ev, fmt.Sprintf("%s dropped listing(s) kept as history for %d days",
				thousandsSep(in.History), in.RetentionDays))
		}
		ev = append(ev, "dates are copied onto a block when it happens, so an explanation "+
			"does not change when the feeds do")
		c.Evidence = ev
	}

	return []Check{c}
}

// thousandsSep groups digits so a long count is readable at a glance.
func thousandsSep(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	out := make([]byte, 0, len(s)+len(s)/3)
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}
