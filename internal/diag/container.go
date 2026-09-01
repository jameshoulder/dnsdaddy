package diag

import "os"

// Runtime is where this process is executing, as far as it can tell from
// inside itself.
//
// It exists for one diagnosis, and that diagnosis was wrong without it.
// On a host, listening on ":8080" means every interface, which on a machine
// with a public address means the internet. Inside a container it means every
// interface *of the container's own network namespace*, and whether any of
// that reaches the outside world is decided by the port mapping the engine was
// given: `127.0.0.1:8080:8080` publishes it to the host's loopback only,
// `0.0.0.0:8080:8080` publishes it to the world. Those two produce an
// identical bind inside the container, and the process cannot see which it
// got. Reporting either as definite public exposure is a guess presented as a
// finding.
type Runtime string

const (
	// RuntimeHost is a process running directly on the machine, where the
	// bind address is the whole story.
	RuntimeHost Runtime = "host"

	// RuntimeContainer is a process inside a container, where the host's port
	// publication is not observable from in here.
	RuntimeContainer Runtime = "container"
)

// containerMarkers are files a container runtime deliberately creates in the
// root filesystem it hands the workload.
//
// Deliberately only these two. /proc/1/cgroup was the traditional signal and
// is not reliable any more: under cgroup v2's unified hierarchy it reads
// "0::/" both inside and outside a container, and grepping it for "docker" has
// produced false positives for host processes whose cgroup path merely
// mentions it. A marker file the runtime writes on purpose is a statement of
// intent rather than a fingerprint.
//
// Getting this wrong is asymmetric, which is why the bar is this high. A false
// "container" downgrades a genuinely public bind from FAIL to WARN — the
// direction that hides a problem — so nothing weaker than an explicit runtime
// marker is allowed to do it.
var containerMarkers = []string{
	"/.dockerenv",        // Docker, every version
	"/run/.containerenv", // Podman
}

// DetectRuntime reports whether this process is inside a container.
//
// Falls back to RuntimeHost whenever it cannot prove otherwise. The host
// answer is the strict one, and a check that is unsure must not be the one
// that relaxes a security finding.
func DetectRuntime() Runtime {
	return detectRuntimeIn(containerMarkers)
}

// detectRuntimeIn is DetectRuntime with the marker list injected, so the test
// suite can prove both branches without needing to be inside a container.
func detectRuntimeIn(markers []string) Runtime {
	for _, marker := range markers {
		if _, err := os.Stat(marker); err == nil {
			return RuntimeContainer
		}
	}
	return RuntimeHost
}
