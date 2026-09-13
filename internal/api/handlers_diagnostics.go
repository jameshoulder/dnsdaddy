package api

import (
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/resources"
)

// DiagnosticsResponse is the answer to "why is DNS not working?".
//
// Authenticated: the checks quote configured CIDRs and network names back at
// the reader, which is exactly what makes them useful and exactly why they do
// not belong on the unauthenticated health endpoint.
type DiagnosticsResponse struct {
	// Status is the worst verdict across every check, so a caller can act on
	// one field.
	Status diag.Status  `json:"status"`
	Checks []diag.Check `json:"checks"`

	// MachineSize describes how large a machine this installation sized
	// itself for.
	MachineSize MachineSize `json:"machineSize"`
}

// MachineSize is how large a machine DNS Daddy is running as.
//
// Two representations on purpose. `size` is for a client that wants to act on
// the value — a settings form choosing the current option, a dashboard
// grouping installations — and is one of a short closed list. `label` and
// `message` are what a person reads, and are the same words doctor prints, so
// a dashboard and a terminal never explain this differently.
type MachineSize struct {
	// Size is "tiny", "small" or "full", or empty on an installation that has
	// not sized itself.
	Size string `json:"size"`
	// Label is the size in words: "1 GB machine", "2 GB machine",
	// "4 GB+ machine".
	Label string `json:"label"`
	// Message is the sentence to show beside it.
	Message string `json:"message"`
	// Automatic reports that the size was chosen from the machine rather than
	// set by the operator.
	Automatic bool `json:"automatic"`
	// LooksLike is what the machine would have been sized as, in words. Worth
	// having separately: it is what makes a mismatch visible.
	LooksLike string `json:"looksLike"`
	// MemoryMB and CPUs are what was read from the machine.
	MemoryMB int `json:"memoryMb"`
	CPUs     int `json:"cpus"`
	// Limits are the ceilings in force, one readable line each.
	Limits []string `json:"limits"`
	// Options are the four settings a client may offer, already labelled.
	Options []MachineSizeOption `json:"options"`
}

// MachineSizeOption is one choice a settings control can present.
type MachineSizeOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// machineSizeOptions is the list every client offers, in this order.
func machineSizeOptions() []MachineSizeOption {
	out := make([]MachineSizeOption, 0, 4)
	for _, p := range []resources.Profile{
		resources.ProfileAuto, resources.ProfileTiny, resources.ProfileSmall, resources.ProfileFull,
	} {
		out = append(out, MachineSizeOption{Value: string(p), Label: p.Label()})
	}
	return out
}

// machineSize renders what this process decided, for the diagnostics response.
func (a *API) machineSize() MachineSize {
	d := a.Sizing
	sized := a.Config
	if d.Applied {
		sized.ApplySize(d.Running)
	}
	return MachineSize{
		Size:      string(d.Running),
		Label:     d.Running.Label(),
		Message:   d.Summary(),
		Automatic: d.Reason == resources.ReasonAutomatic,
		LooksLike: d.Detected.Label(),
		MemoryMB:  d.Machine.MemoryMB,
		CPUs:      d.Machine.CPUs,
		Limits:    sized.LimitsInForce(),
		Options:   machineSizeOptions(),
	}
}

func (a *API) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies, err := a.Store.ListPolicies(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	refused := a.DNS.RefusedClients()
	stale := a.ClientACL.Stale()
	checks := diag.ClientAccess(diag.ClientAccessInput{
		ACL: a.ClientACL.Current(),
		// Always known here: this handler runs inside the daemon that owns
		// the flag.
		Stale:          &stale,
		Networks:       diag.FromStoreNetworks(networks, diag.PolicyNames(policies)),
		RefusedQueries: &refused,
	})

	// Evidence the process has actually gathered about its own exposure. It
	// belongs beside the client-access checks: both answer "is this reachable
	// by the people it should be, and only by them?".
	exposureCount, exposureAddr := a.exposure.snapshot()
	checks = append(checks, diag.ManagementExposure(exposureCount, exposureAddr))

	// The machine-size checks are appended so that "why is DNS not working?"
	// and "why is this box slow?" are answered by the same call.
	checks = append(checks, diag.MachineSize(diag.MachineSizeInput{
		Sizing:           a.Sizing,
		Limits:           a.machineSize().Limits,
		DecisionRecords:  a.Config.Log.DecisionRecords,
		LocalDNSSECLearn: a.Config.DNS.LocalDNSSECValidation == config.LocalDNSSECObserve,
		WALBytes:         a.Store.WALBytes(),
	})...)

	writeJSON(w, http.StatusOK, DiagnosticsResponse{
		Status:      diag.Worst(checks),
		Checks:      checks,
		MachineSize: a.machineSize(),
	})
}
