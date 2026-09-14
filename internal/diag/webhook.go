package diag

import (
	"fmt"
	"time"
)

// NotificationsInput describes where findings are sent, if anywhere.
type NotificationsInput struct {
	// Configured reports that an address is set. False is the default and a
	// perfectly normal state.
	Configured bool
	// Address is the endpoint with anything secret already removed. Never the
	// raw URL: a webhook address is often a bearer token in path form.
	Address string
	// URLError is why a configured address cannot be used, if it cannot.
	URLError string

	Sent     uint64
	Dropped  map[string]uint64
	QueueLen int
	// LastSendAt is when something last arrived. Zero means nothing has been
	// sent yet, which on a quiet network is the usual state.
	LastSendAt time.Time
	// LastError is the most recent failure, already redacted.
	LastError string
}

// TotalDropped sums every reason.
func (in NotificationsInput) TotalDropped() uint64 {
	var n uint64
	for _, v := range in.Dropped {
		n += v
	}
	return n
}

// Notifications reports whether findings are being sent anywhere, and whether
// that is working.
//
// One line when nothing is configured, and it is a PASS. Sending findings off
// the machine is a choice, not a missing step: the default is that they stay
// here, and a check that nagged about it would be telling an operator their
// correct configuration is wrong. On a 1 GB box it is also the right default.
func Notifications(in NotificationsInput) []Check {
	c := Check{Section: SectionSystem, Name: "Finding notifications"}

	switch {
	case !in.Configured && in.URLError == "":
		c.Status = StatusPass
		c.Summary = "Findings stay on this machine. Add a notification address if you " +
			"want them sent to Slack, Teams, or another tool."

	case in.URLError != "":
		// A configured address that cannot be used. This is the one failure
		// here, and it is a failure because the operator asked for something
		// that will never happen and nothing else would tell them.
		c.Status = StatusFail
		c.Summary = "The notification address cannot be used, so no findings are being sent."
		c.Evidence = []string{in.URLError}
		c.Action = "Correct the address. It must start with https:// and point at an " +
			"address on the internet — not at this machine or your own network."

	case in.TotalDropped() > 0 || in.LastError != "":
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("Some findings did not reach %s.", in.Address)
		ev := []string{fmt.Sprintf("%d sent, %d not delivered", in.Sent, in.TotalDropped())}
		if in.LastError != "" {
			ev = append(ev, "most recent failure: "+in.LastError)
		}
		if n := in.Dropped[dropFull]; n > 0 {
			ev = append(ev, fmt.Sprintf("%d were dropped because findings arrived faster "+
				"than the endpoint accepted them", n))
		}
		ev = append(ev, "every finding is still in the database and in the findings file, "+
			"whether or not it was sent")
		c.Evidence = ev
		c.Action = "Check the endpoint is reachable and accepting. Nothing has been lost " +
			"— this is about notifications, not records."

	default:
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("Findings are sent to %s.", in.Address)
		ev := []string{fmt.Sprintf("%d sent", in.Sent)}
		if in.LastSendAt.IsZero() {
			ev = append(ev, "nothing has been sent yet, which is normal on a quiet network")
		} else {
			ev = append(ev, "most recent: "+in.LastSendAt.UTC().Format(time.RFC3339))
		}
		c.Evidence = ev
	}

	return []Check{c}
}

// dropFull mirrors detect.WebhookDropFull without importing it: this package
// takes plain values so that diagnostics do not depend on the packages they
// describe.
const dropFull = "full"
