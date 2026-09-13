// Package resources decides how much of itself DNS Daddy should use on the
// machine it has been given.
//
// # Why this exists
//
// The reference deployment is a 1 GB VPS. The defaults everywhere else in this
// repository were chosen for that box, which means a 4 GB machine runs the
// same small caps and a 512 MB container runs caps it cannot afford. Asking
// the operator to work that out — and to know which of a dozen settings are
// the memory-expensive ones — is asking them to be a performance engineer to
// run a DNS server.
//
// So the program looks at the machine once, at startup, picks a size, and
// applies the caps for it. The operator can choose a different size. That is
// the whole of the interface.
//
// # What this package will not do
//
// It never turns a feature on. Growing a machine raises how much history and
// state the resolver will hold; it does not start recording decisions or
// validating DNSSEC locally, because those are choices about what the software
// does rather than about how much memory it may use, and inheriting one from a
// hardware change is not a decision the operator made. Retiring a feature
// works the same way in reverse: the protection path — filtering, the client
// ACL, the rate limiter, the rebinding filter — is identical on every size.
//
// It also never changes its mind while the process is running. A size is
// chosen at startup and held. Reacting to memory pressure mid-query would make
// the resolver's behaviour depend on what the rest of the box was doing, which
// is precisely the kind of thing that is impossible to reason about at 3am.
package resources

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Profile is how large a machine DNS Daddy is sizing itself for.
//
// The stored and configured values stay machine-readable; Label turns one into
// the words an operator sees.
type Profile string

const (
	// ProfileAuto means "look at the machine". It is never a running state:
	// Choose resolves it to one of the three below before anything is applied.
	ProfileAuto Profile = "auto"
	// ProfileTiny is the 1 GB reference deployment — a Linode Nanode and its
	// equivalents.
	ProfileTiny Profile = "tiny"
	// ProfileSmall is a 2 GB machine.
	ProfileSmall Profile = "small"
	// ProfileFull is 4 GB and up.
	ProfileFull Profile = "full"
)

// Label is the profile in the words used everywhere an operator reads.
//
// There is exactly one set of these, and every surface — doctor, the
// diagnostics API, the dashboard — renders from it, so the four names cannot
// drift apart between the places somebody might look.
func (p Profile) Label() string {
	switch p {
	case ProfileAuto:
		return "Automatic (recommended)"
	case ProfileTiny:
		return "1 GB machine"
	case ProfileSmall:
		return "2 GB machine"
	case ProfileFull:
		return "4 GB+ machine"
	}
	return string(p)
}

// Valid reports whether p is one of the four settings.
func (p Profile) Valid() bool {
	switch p {
	case ProfileAuto, ProfileTiny, ProfileSmall, ProfileFull:
		return true
	}
	return false
}

// DefaultSentence is shown wherever the running size appears.
//
// One sentence, in one constant, because it is the only explanation most
// operators will ever read about this feature and it should say the same thing
// in every place it appears.
const DefaultSentence = "DNS Daddy sized itself for this machine. You can pick a different size if that is wrong."

// Memory sources, reported so an operator can see which one answered.
const (
	// SourceContainerLimit is a memory limit set on this container.
	SourceContainerLimit = "container limit"
	// SourceMachineMemory is the machine's total memory, used when no
	// container limit is set.
	SourceMachineMemory = "machine memory"
	// SourceConfigured is an explicit memory_mb in the configuration.
	SourceConfigured = "configured"
	// SourceUnknown means nothing could be read. See Detected.Unreadable.
	SourceUnknown = "unknown"
)

// Reserve defaults, in MB.
const (
	// DefaultReservedMB is what is left for the operating system, the shell
	// somebody SSHs in with, and the page cache the database depends on.
	DefaultReservedMB = 256
	// SharedHostReservedMB is used when this process is in a container with no
	// memory limit of its own. The number it can see is the whole machine's
	// memory, which it is sharing with the container runtime and everything
	// else on the box, so more of it belongs to somebody else.
	SharedHostReservedMB = 384
)

// Detected is one look at the machine.
type Detected struct {
	// MemoryMB is what was read, before the reserve.
	MemoryMB int
	// ReservedMB is what was set aside for everything that is not DNS Daddy.
	ReservedMB int
	// AvailableMB is MemoryMB minus ReservedMB, floored at zero. This is the
	// number the size is chosen from.
	AvailableMB int
	// CPUs is how many processors this process may use.
	CPUs int
	// MemorySource names which of the sources above answered.
	MemorySource string
	// Unreadable means nothing could be read about memory and the smallest
	// size was assumed.
	//
	// Assuming small is the safe direction: caps that are too low on a large
	// machine waste memory nobody notices, and caps that are too high on a
	// small one get the process killed.
	Unreadable bool
	// InContainer reports that this looks like a container.
	InContainer bool
}

// Options configures a detection run. The zero value reads the real machine.
type Options struct {
	// Root is the filesystem to read from. Nil means the real one. Tests pass
	// a fake so that classification can be exercised without the machine the
	// test happens to run on having any say in it.
	Root fs.FS
	// MemoryMB overrides detection entirely when non-zero.
	MemoryMB int
	// ReservedMB overrides the reserve when non-zero.
	ReservedMB int
	// NumCPU overrides the processor count. Nil means runtime.NumCPU.
	NumCPU func() int
}

// Detect reads what it can about the machine.
//
// It never returns an error. There is no useful thing for a DNS server to do
// with "I could not tell how much memory this box has" except assume the
// smallest size and say so, which is what Unreadable is for — failing to start
// over it would turn an unfamiliar container runtime into an outage.
func Detect(o Options) Detected {
	root := o.Root
	if root == nil {
		root = os.DirFS("/")
	}
	numCPU := o.NumCPU
	if numCPU == nil {
		numCPU = runtime.NumCPU
	}

	d := Detected{CPUs: cpus(root, numCPU)}
	d.InContainer = inContainer(root)

	switch {
	case o.MemoryMB > 0:
		d.MemoryMB, d.MemorySource = o.MemoryMB, SourceConfigured
	default:
		d.MemoryMB, d.MemorySource = memoryMB(root)
	}

	switch {
	case o.ReservedMB > 0:
		d.ReservedMB = o.ReservedMB
	case d.InContainer && d.MemorySource == SourceMachineMemory:
		// A container with no limit of its own: the figure just read is the
		// whole machine, and this process is not the only thing on it.
		d.ReservedMB = SharedHostReservedMB
	default:
		d.ReservedMB = DefaultReservedMB
	}

	if d.MemoryMB <= 0 {
		d.Unreadable = true
		d.MemorySource = SourceUnknown
		d.AvailableMB = 0
		return d
	}
	if d.AvailableMB = d.MemoryMB - d.ReservedMB; d.AvailableMB < 0 {
		d.AvailableMB = 0
	}
	return d
}

// Thresholds, in MB of memory available after the reserve.
//
// The boundaries sit well below the round numbers they describe, because the
// round numbers are marketing rather than measurements: a "1 GB" VPS reports
// somewhere around 970 MB once the kernel has taken its share, and a machine
// that classified itself one size up because of that would apply caps it
// cannot afford.
const (
	// tinyCeiling: below this, the 1 GB caps.
	tinyCeiling = 1280
	// singleCPUCeiling extends the smallest size upward on a one-processor
	// box. Memory is only half the question — feed rebuilds, detector
	// evaluation and the database's own work all compete for one processor,
	// and holding more state on a machine that cannot process it produces
	// latency rather than capability.
	singleCPUCeiling = 1536
	// smallCeiling: below this, the 2 GB caps.
	smallCeiling = 3584
)

// Choose picks a size from what was detected.
func Choose(d Detected) Profile {
	if d.Unreadable {
		return ProfileTiny
	}
	switch {
	case d.AvailableMB < tinyCeiling:
		return ProfileTiny
	case d.AvailableMB < singleCPUCeiling && d.CPUs <= 1:
		return ProfileTiny
	case d.AvailableMB < smallCeiling:
		return ProfileSmall
	}
	return ProfileFull
}

// Resolve turns the configured setting into a running size, and reports
// whether the machine was consulted.
func Resolve(configured Profile, d Detected) (running Profile, automatic bool) {
	if configured == "" || configured == ProfileAuto {
		return Choose(d), true
	}
	return configured, false
}

// Describe is the one-line summary of a detection, for logs and for the
// evidence lines under a doctor check.
func (d Detected) Describe() string {
	if d.Unreadable {
		return "could not read this machine's memory"
	}
	cpu := "processors"
	if d.CPUs == 1 {
		cpu = "processor"
	}
	return fmt.Sprintf("%s MB memory (%s), %d MB left for everything else, %d %s",
		thousands(d.MemoryMB), d.MemorySource, d.ReservedMB, d.CPUs, cpu)
}

// thousands formats a number with separators, because "1024" and "10240" are
// easy to misread at a glance in a wall of diagnostic output.
func thousands(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// memoryMB reads the memory limit that applies to this process.
//
// Order matters: a limit set on the container is the real ceiling, and the
// machine's total memory is only relevant when there is no such limit. Reading
// them the other way round is the classic way to get a container killed —
// the process sizes itself for a 64 GB host and is capped at 512 MB.
func memoryMB(root fs.FS) (int, string) {
	// A limit set on this container, current style.
	if raw, err := fs.ReadFile(root, "sys/fs/cgroup/memory.max"); err == nil {
		if n, ok := parseLimitBytes(string(raw)); ok {
			if mb, ok := megabytes(n); ok {
				return mb, SourceContainerLimit
			}
		}
	}
	// A limit set on this container, older style. Unset here is not "max" but
	// a number so large it means the same thing, so it is treated as absent
	// rather than as a limit of eight million terabytes.
	if raw, err := fs.ReadFile(root, "sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if n, ok := parseLimitBytes(string(raw)); ok {
			if mb, ok := megabytes(n); ok {
				return mb, SourceContainerLimit
			}
		}
	}
	if raw, err := fs.ReadFile(root, "proc/meminfo"); err == nil {
		if kb, ok := parseMemTotalKB(string(raw)); ok {
			if mb, ok := megabytes(kb * 1024); ok {
				return mb, SourceMachineMemory
			}
		}
	}
	return 0, SourceUnknown
}

// maxPlausibleMB is the largest machine this will believe in: 16 TB.
//
// Everything above it is treated as no limit at all, which covers the two ways
// these files say "unlimited" without a word for it — the older limit style's
// near-maximum sentinel, and any value a filesystem that is not really a
// kernel interface might contain. Believing one would size for a machine that
// does not exist, and on a 32-bit build the conversion would wrap outright.
const maxPlausibleMB = 16 << 20

// megabytes converts a byte count, refusing anything that cannot be a real
// machine. The second return is false for "treat this as unreadable".
func megabytes(bytes uint64) (int, bool) {
	mb := bytes / (1 << 20)
	if mb == 0 || mb > maxPlausibleMB {
		return 0, false
	}
	return int(mb), true
}

// parseLimitBytes reads a byte count, treating "max" and anything unparseable
// as no limit.
func parseLimitBytes(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

// parseMemTotalKB pulls MemTotal out of the kernel's memory summary.
func parseMemTotalKB(s string) (uint64, bool) {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || n == 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// cpus reads how many processors this process may use.
//
// A quota is a fraction of a processor's time rather than a count, so 1.5
// rounds up to 2: a process allowed half of a second processor can genuinely
// run work on it, and rounding down would classify a machine as
// single-processor when it is not.
func cpus(root fs.FS, fallback func() int) int {
	if raw, err := fs.ReadFile(root, "sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) == 2 && fields[0] != "max" {
			quota, qerr := strconv.ParseFloat(fields[0], 64)
			period, perr := strconv.ParseFloat(fields[1], 64)
			if qerr == nil && perr == nil && quota > 0 && period > 0 {
				if n := int((quota + period - 1) / period); n >= 1 {
					return n
				}
				return 1
			}
		}
	}
	if raw, err := fs.ReadFile(root, "sys/fs/cgroup/cpuset.cpus.effective"); err == nil {
		if n := countCPUSet(string(raw)); n > 0 {
			return n
		}
	}
	if n := fallback(); n > 0 {
		return n
	}
	return 1
}

// countCPUSet counts the processors in a list such as "0-3,7".
func countCPUSet(s string) int {
	total := 0
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			if _, err := strconv.Atoi(part); err == nil {
				total++
			}
			continue
		}
		a, aerr := strconv.Atoi(lo)
		b, berr := strconv.Atoi(hi)
		if aerr == nil && berr == nil && b >= a {
			total += b - a + 1
		}
	}
	return total
}

// containerMarkers are the files whose presence means "this is a container".
var containerMarkers = []string{".dockerenv", "run/.containerenv"}

// inContainer reports whether this looks like a container.
//
// Best effort by nature: container runtimes are not obliged to leave a mark,
// and the only thing this changes is how much memory is set aside on a
// container that has no limit of its own. Guessing wrong in either direction
// moves one reserve figure, never whether a feature runs.
func inContainer(root fs.FS) bool {
	for _, marker := range containerMarkers {
		if _, err := fs.Stat(root, marker); err == nil {
			return true
		}
	}
	if raw, err := fs.ReadFile(root, "proc/1/cgroup"); err == nil {
		s := string(raw)
		for _, needle := range []string{"docker", "containerd", "kubepods", "lxc", "podman"} {
			if strings.Contains(s, needle) {
				return true
			}
		}
	}
	return false
}
