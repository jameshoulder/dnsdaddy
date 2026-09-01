package diag

import (
	"os"
	"path/filepath"
	"testing"
)

// The detection has to be provable in both directions without the test process
// actually being inside a container, which is why detectRuntimeIn takes the
// marker list.
func TestRuntimeDetectionRequiresAnExplicitRuntimeMarker(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "dockerenv")
	if err := os.WriteFile(present, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "not-here")

	if got := detectRuntimeIn([]string{absent}); got != RuntimeHost {
		t.Errorf("no marker present = %q, want %q", got, RuntimeHost)
	}
	if got := detectRuntimeIn([]string{present}); got != RuntimeContainer {
		t.Errorf("marker present = %q, want %q", got, RuntimeContainer)
	}
	// Any one of the list is enough: Docker writes the first, Podman the
	// second, and a workload sees exactly one of them.
	if got := detectRuntimeIn([]string{absent, present}); got != RuntimeContainer {
		t.Errorf("second marker present = %q, want %q", got, RuntimeContainer)
	}
	// An empty list is the "no evidence" case and must give the strict answer.
	if got := detectRuntimeIn(nil); got != RuntimeHost {
		t.Errorf("no markers to check = %q, want %q", got, RuntimeHost)
	}
}

// The marker list is the whole security argument for downgrading a wildcard
// bind, so what is in it is worth pinning.
//
// /proc/1/cgroup is deliberately absent. Under cgroup v2's unified hierarchy
// it reads "0::/" both inside and outside a container, and grepping its text
// for "docker" has produced false positives on hosts. A false "container" turns
// a real public bind from FAIL into WARN, so only a file a runtime writes on
// purpose is allowed to do it.
func TestContainerMarkersAreRuntimeWrittenFilesOnly(t *testing.T) {
	want := map[string]bool{"/.dockerenv": true, "/run/.containerenv": true}
	if len(containerMarkers) != len(want) {
		t.Fatalf("marker list is %v, want exactly %d entries", containerMarkers, len(want))
	}
	for _, m := range containerMarkers {
		if !want[m] {
			t.Errorf("unexpected container marker %q — is it something a host can have?", m)
		}
	}
}

// DetectRuntime is what the doctor calls. On this test machine the answer is
// whatever it is; what must hold is that it is one of the two values and that
// it agrees with the marker check, so the exported entry point cannot drift
// away from the tested one.
func TestDetectRuntimeAgreesWithTheMarkerCheck(t *testing.T) {
	got := DetectRuntime()
	if got != RuntimeHost && got != RuntimeContainer {
		t.Fatalf("DetectRuntime() = %q, want host or container", got)
	}
	if want := detectRuntimeIn(containerMarkers); got != want {
		t.Errorf("DetectRuntime() = %q but detectRuntimeIn(containerMarkers) = %q", got, want)
	}
}
