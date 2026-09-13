package resources

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// machine builds a fake filesystem so that classification can be tested
// without the machine running the test having a vote. Every case below would
// otherwise pass or fail depending on the CI runner's memory, which is the
// opposite of a test.
type machine struct {
	cgroupV2Max   string // sys/fs/cgroup/memory.max
	cgroupV1Limit string // sys/fs/cgroup/memory/memory.limit_in_bytes
	memInfo       string // proc/meminfo
	cpuMax        string // sys/fs/cgroup/cpu.max
	cpuSet        string // sys/fs/cgroup/cpuset.cpus.effective
	dockerEnv     bool
	pidCgroup     string
}

func (m machine) fs() fs.FS {
	f := fstest.MapFS{}
	add := func(path, content string) {
		if content != "" {
			f[path] = &fstest.MapFile{Data: []byte(content)}
		}
	}
	add("sys/fs/cgroup/memory.max", m.cgroupV2Max)
	add("sys/fs/cgroup/memory/memory.limit_in_bytes", m.cgroupV1Limit)
	add("proc/meminfo", m.memInfo)
	add("sys/fs/cgroup/cpu.max", m.cpuMax)
	add("sys/fs/cgroup/cpuset.cpus.effective", m.cpuSet)
	add("proc/1/cgroup", m.pidCgroup)
	if m.dockerEnv {
		f[".dockerenv"] = &fstest.MapFile{}
	}
	return f
}

func memInfoMB(mb int) string {
	return "MemFree:          123456 kB\nMemTotal:       " +
		itoa(mb*1024) + " kB\nBuffers:            1234 kB\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func detect(t *testing.T, m machine, cpus int) Detected {
	t.Helper()
	return Detect(Options{Root: m.fs(), NumCPU: func() int { return cpus }})
}

// TestAMemoryLimitOnTheContainerBeatsTheMachineTotal.
//
// This is the one that matters most in practice. A container on a 64 GB host
// with a 512 MB limit that read the host's total would size itself twenty
// times too large and be killed the first time the blocklist rebuilt. The
// limit is the ceiling; the host's total is only relevant when there is none.
func TestAMemoryLimitOnTheContainerBeatsTheMachineTotal(t *testing.T) {
	d := detect(t, machine{
		cgroupV2Max: "536870912\n",        // 512 MB
		memInfo:     memInfoMB(64 * 1024), // a 64 GB host
	}, 8)

	if d.MemoryMB != 512 {
		t.Fatalf("memory = %d MB, want 512 — the host total was read instead of the limit", d.MemoryMB)
	}
	if d.MemorySource != SourceContainerLimit {
		t.Errorf("source = %q, want %q", d.MemorySource, SourceContainerLimit)
	}
	if got := Choose(d); got != ProfileTiny {
		t.Errorf("512 MB classified as %q, want tiny", got)
	}
}

// TestTheThreeSizesAreChosenFromTheMemoryLimit walks the boundaries the
// published figures promise.
func TestTheThreeSizesAreChosenFromTheMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes string
		cpus  int
		want  Profile
	}{
		{"512Mi", "536870912", 2, ProfileTiny},
		{"1Gi", "1073741824", 2, ProfileTiny},
		{"2Gi", "2147483648", 2, ProfileSmall},
		{"2Gi one processor", "2147483648", 1, ProfileSmall},
		{"4Gi", "4294967296", 2, ProfileFull},
		{"8Gi", "8589934592", 4, ProfileFull},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := detect(t, machine{cgroupV2Max: tc.bytes + "\n"}, tc.cpus)
			if got := Choose(d); got != tc.want {
				t.Errorf("%s with %d processors (%d MB available) chose %q, want %q",
					tc.name, tc.cpus, d.AvailableMB, got, tc.want)
			}
		})
	}
}

// TestAOneProcessorBoxStaysOnTheSmallestSizeForLonger.
//
// Memory is only half of what a size decides. On one processor the feed
// rebuild, the detectors and the database all queue behind each other, so
// holding more state produces latency rather than capability. 1.4 GB with two
// processors is a 2 GB machine; the same memory with one is not.
func TestAOneProcessorBoxStaysOnTheSmallestSizeForLonger(t *testing.T) {
	const memory = "1503238553" // ~1434 MB, so ~1178 MB available

	two := detect(t, machine{cgroupV2Max: memory}, 2)
	one := detect(t, machine{cgroupV2Max: memory}, 1)
	if two.AvailableMB != one.AvailableMB {
		t.Fatalf("the two cases differ in memory (%d vs %d), so this proves nothing",
			two.AvailableMB, one.AvailableMB)
	}

	// Both are below the ceiling here, so raise it to where only the processor
	// count separates them.
	const bigger = "1879048192" // 1792 MB, so 1536 MB available
	two = detect(t, machine{cgroupV2Max: bigger}, 2)
	one = detect(t, machine{cgroupV2Max: bigger}, 1)
	if got := Choose(two); got != ProfileSmall {
		t.Errorf("1536 MB available with two processors chose %q, want small", got)
	}
	if got := Choose(one); got != ProfileSmall {
		t.Errorf("1536 MB available with one processor chose %q, want small "+
			"(the single-processor ceiling is %d, exclusive)", got, singleCPUCeiling)
	}

	// Just under the single-processor ceiling is where they part.
	const under = "1782579200" // 1700 MB, so 1444 MB available
	if got := Choose(detect(t, machine{cgroupV2Max: under}, 2)); got != ProfileSmall {
		t.Errorf("1444 MB with two processors chose %q, want small", got)
	}
	if got := Choose(detect(t, machine{cgroupV2Max: under}, 1)); got != ProfileTiny {
		t.Errorf("1444 MB with one processor chose %q, want tiny", got)
	}
}

// TestTheOlderContainerLimitStyleIsReadAndItsUnsetValueIgnored.
//
// The older style has no word for "no limit": an unlimited container carries a
// number near the top of a 64-bit integer. Reading that as a limit would
// classify every such box as enormous, which is the wrong direction to be
// wrong in.
func TestTheOlderContainerLimitStyleIsReadAndItsUnsetValueIgnored(t *testing.T) {
	d := detect(t, machine{cgroupV1Limit: "2147483648\n"}, 2)
	if d.MemoryMB != 2048 || d.MemorySource != SourceContainerLimit {
		t.Errorf("got %d MB from %q, want 2048 from a container limit", d.MemoryMB, d.MemorySource)
	}

	unlimited := detect(t, machine{
		cgroupV1Limit: "9223372036854771712\n",
		memInfo:       memInfoMB(1024),
	}, 1)
	if unlimited.MemorySource != SourceMachineMemory {
		t.Errorf("source = %q, want the machine total: the unset sentinel was read as a limit",
			unlimited.MemorySource)
	}
	if unlimited.MemoryMB != 1024 {
		t.Errorf("memory = %d MB, want 1024", unlimited.MemoryMB)
	}
}

// TestAPlainOneGigabyteMachineWithNoContainerLimitIsTheSmallestSize —
// the reference deployment, read the way it really presents.
func TestAPlainOneGigabyteMachineWithNoContainerLimitIsTheSmallestSize(t *testing.T) {
	d := detect(t, machine{memInfo: memInfoMB(1024)}, 1)
	if d.MemorySource != SourceMachineMemory {
		t.Fatalf("source = %q", d.MemorySource)
	}
	if d.ReservedMB != DefaultReservedMB {
		t.Errorf("reserved %d MB, want %d on a machine that is not a container",
			d.ReservedMB, DefaultReservedMB)
	}
	if d.AvailableMB != 768 {
		t.Errorf("available = %d MB, want 768", d.AvailableMB)
	}
	if got := Choose(d); got != ProfileTiny {
		t.Errorf("a 1 GB box chose %q, want tiny", got)
	}
}

// TestAContainerWithNoLimitOfItsOwnSetsMoreAside.
//
// The number it can read is the whole machine, and it is sharing that machine
// with the container runtime and whatever else is on the box. Reserving the
// same amount as a dedicated VPS would over-commit it.
func TestAContainerWithNoLimitOfItsOwnSetsMoreAside(t *testing.T) {
	bare := detect(t, machine{memInfo: memInfoMB(2048)}, 2)
	contained := detect(t, machine{memInfo: memInfoMB(2048), dockerEnv: true}, 2)

	if bare.ReservedMB != DefaultReservedMB {
		t.Errorf("a plain machine reserved %d MB, want %d", bare.ReservedMB, DefaultReservedMB)
	}
	if contained.ReservedMB != SharedHostReservedMB {
		t.Errorf("a container with no limit reserved %d MB, want %d",
			contained.ReservedMB, SharedHostReservedMB)
	}
	if !contained.InContainer {
		t.Error("the container was not recognised as one")
	}

	// A container that does have a limit is reading its own ceiling, not the
	// machine's, so the larger reserve would be double-counting.
	limited := detect(t, machine{cgroupV2Max: "2147483648", memInfo: memInfoMB(64 * 1024), dockerEnv: true}, 2)
	if limited.ReservedMB != DefaultReservedMB {
		t.Errorf("a container with its own limit reserved %d MB, want %d",
			limited.ReservedMB, DefaultReservedMB)
	}
}

// TestAnUnreadableMachineAssumesTheSmallestSizeAndSaysSo.
//
// Refusing to start because an unfamiliar container runtime laid its files out
// differently would turn a cosmetic problem into an outage. Assuming small is
// the safe direction: caps too low on a big machine waste memory nobody
// notices; caps too high on a small one get the process killed.
func TestAnUnreadableMachineAssumesTheSmallestSizeAndSaysSo(t *testing.T) {
	d := Detect(Options{Root: fstest.MapFS{}, NumCPU: func() int { return 4 }})
	if !d.Unreadable {
		t.Fatal("an empty filesystem was not reported as unreadable")
	}
	if d.MemorySource != SourceUnknown {
		t.Errorf("source = %q, want %q", d.MemorySource, SourceUnknown)
	}
	if got := Choose(d); got != ProfileTiny {
		t.Errorf("an unreadable machine chose %q, want tiny", got)
	}
	if !strings.Contains(d.Describe(), "could not read") {
		t.Errorf("Describe() = %q, which does not say the reading failed", d.Describe())
	}
}

// TestGarbageInTheMemoryFilesDoesNotPanicAndDoesNotLie. Every one of these has
// been seen in the wild or is one typo away from it.
func TestGarbageInTheMemoryFilesDoesNotPanicAndDoesNotLie(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    machine
	}{
		{"empty limit file", machine{cgroupV2Max: ""}},
		{"max", machine{cgroupV2Max: "max\n"}},
		{"not a number", machine{cgroupV2Max: "banana\n"}},
		{"zero", machine{cgroupV2Max: "0\n"}},
		{"meminfo with no MemTotal", machine{memInfo: "MemFree: 100 kB\n"}},
		{"MemTotal with no value", machine{memInfo: "MemTotal:\n"}},
		{"MemTotal not a number", machine{memInfo: "MemTotal:   lots kB\n"}},
		{"MemTotal zero", machine{memInfo: "MemTotal:   0 kB\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := detect(t, tc.m, 1)
			if !d.Unreadable {
				t.Errorf("%q produced %d MB from %q rather than an honest failure",
					tc.name, d.MemoryMB, d.MemorySource)
			}
			if got := Choose(d); got != ProfileTiny {
				t.Errorf("chose %q, want tiny", got)
			}
		})
	}
}

// TestProcessorCountPrefersTheLimitOverTheHostsCount, for the same reason
// memory does: a container allowed one processor on a 32-core host has one.
func TestProcessorCountPrefersTheLimitOverTheHostsCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    machine
		host int
		want int
	}{
		{"quota of one processor", machine{cpuMax: "100000 100000\n"}, 32, 1},
		{"quota of half a processor", machine{cpuMax: "50000 100000\n"}, 32, 1},
		{"quota of one and a half", machine{cpuMax: "150000 100000\n"}, 32, 2},
		{"quota of four", machine{cpuMax: "400000 100000\n"}, 32, 4},
		{"no quota falls through to the set", machine{cpuMax: "max 100000\n", cpuSet: "0-3\n"}, 32, 4},
		{"a set with a gap", machine{cpuSet: "0-1,7\n"}, 32, 3},
		{"a single processor in the set", machine{cpuSet: "2\n"}, 32, 1},
		{"nothing readable falls back to the host", machine{}, 8, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := detect(t, tc.m, tc.host).CPUs; got != tc.want {
				t.Errorf("got %d processors, want %d", got, tc.want)
			}
		})
	}
}

// TestChoosingAnExplicitSizeIgnoresTheMachine, and reports that it did — the
// difference is what lets doctor warn about a mismatch instead of silently
// obeying a setting that will get the box killed.
func TestChoosingAnExplicitSizeIgnoresTheMachine(t *testing.T) {
	small := detect(t, machine{cgroupV2Max: "536870912"}, 1) // 512 MB

	running, automatic := Resolve(ProfileFull, small)
	if running != ProfileFull {
		t.Errorf("an explicit choice was overridden: got %q", running)
	}
	if automatic {
		t.Error("an explicit choice was reported as automatic")
	}

	running, automatic = Resolve(ProfileAuto, small)
	if running != ProfileTiny || !automatic {
		t.Errorf("Resolve(auto) = %q/%v, want tiny/true", running, automatic)
	}

	// An empty setting is the same as automatic: a configuration file that
	// omits the key must behave like one that asks for the default.
	if running, automatic = Resolve("", small); running != ProfileTiny || !automatic {
		t.Errorf(`Resolve("") = %q/%v, want tiny/true`, running, automatic)
	}
}

// TestEveryProfileHasWordsAnOperatorCanRead. The labels are the whole
// interface, so they are asserted rather than assumed.
func TestEveryProfileHasWordsAnOperatorCanRead(t *testing.T) {
	want := map[Profile]string{
		ProfileAuto:  "Automatic (recommended)",
		ProfileTiny:  "1 GB machine",
		ProfileSmall: "2 GB machine",
		ProfileFull:  "4 GB+ machine",
	}
	for p, label := range want {
		if got := p.Label(); got != label {
			t.Errorf("%q reads as %q, want %q", p, got, label)
		}
		if !p.Valid() {
			t.Errorf("%q is not accepted as a setting", p)
		}
	}
	if Profile("enormous").Valid() {
		t.Error("an unknown size was accepted")
	}
}

// TestAnImplausibleMemoryFigureIsTreatedAsUnreadable.
//
// These files have no word for "unlimited". The older limit style writes a
// number near the maximum of a 64-bit integer, and a filesystem that is not
// really a kernel interface can contain anything at all. Believing one would
// size this process for a machine that does not exist — and on a 32-bit build
// the conversion wraps outright, which could produce a negative figure and
// therefore any size at all.
func TestAnImplausibleMemoryFigureIsTreatedAsUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		m     machine
		wantS string
	}{
		{"the older style's unlimited sentinel",
			machine{cgroupV1Limit: "9223372036854771712\n"}, SourceUnknown},
		{"the maximum a 64-bit integer holds",
			machine{cgroupV2Max: "18446744073709551615\n"}, SourceUnknown},
		{"a limit under one megabyte",
			machine{cgroupV2Max: "1024\n"}, SourceUnknown},
		{"an absurd machine total",
			machine{memInfo: "MemTotal: 99999999999999999 kB\n"}, SourceUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := detect(t, tc.m, 1)
			if d.MemorySource != tc.wantS {
				t.Errorf("source = %q (%d MB), want %q", d.MemorySource, d.MemoryMB, tc.wantS)
			}
			if d.MemoryMB < 0 {
				t.Errorf("memory = %d MB, which is not a quantity", d.MemoryMB)
			}
			if got := Choose(d); got != ProfileTiny {
				t.Errorf("chose %q, want tiny", got)
			}
		})
	}

	// And an implausible limit still falls through to a readable machine
	// total, rather than poisoning the whole reading.
	d := detect(t, machine{
		cgroupV1Limit: "9223372036854771712\n",
		memInfo:       memInfoMB(2048),
	}, 2)
	if d.MemorySource != SourceMachineMemory || d.MemoryMB != 2048 {
		t.Errorf("got %d MB from %q, want 2048 from the machine total", d.MemoryMB, d.MemorySource)
	}

	// A real 16 TB machine is still believed: the ceiling exists to reject
	// sentinels, not to cap what this can run on.
	big := detect(t, machine{memInfo: memInfoMB(1 << 20)}, 32) // 1 TB
	if big.MemorySource != SourceMachineMemory {
		t.Errorf("a 1 TB machine was rejected: %q", big.MemorySource)
	}
	if got := Choose(big); got != ProfileFull {
		t.Errorf("a 1 TB machine chose %q, want full", got)
	}
}
