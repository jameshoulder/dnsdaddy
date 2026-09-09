package daddybound_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/jameshoulder/dnsdaddy"

// Daddybound may now be reached from the query path, but only through one
// door and only as far as two packages. This test is what makes that a
// property of the build rather than a convention.
//
// Until observe mode, the rule was simply "the query path cannot reach
// Daddybound", enforced here. That rule has served its purpose and could not
// survive this milestone: dnsserver has to be able to hand a resolved query to
// the observer. Deleting the test rather than replacing it would have thrown
// away the part that still matters, which is *which* packages may be reached
// and by whom.
//
// Three things are asserted, and each would let something specific go wrong if
// it were dropped.
//
// The resolver, the policy engine, the blocklist, the query log and the store
// still cannot reach Daddybound at all. Those are the packages that decide and
// deliver an answer, and an import from any of them would be the beginning of
// a verdict influencing one. Only dnsserver has a door, and it is the one
// place where the answer is already final.
//
// Nothing on the query path may reach the laboratory or the differential
// harness. Those generate keys, sign zones, and shell out to reference
// validators; they exist to be adversarial and belong nowhere near a process
// answering real queries.
//
// And the door itself is narrow: dnsserver may reach the observer and the
// validation engine, and nothing else under internal/daddybound.
func TestTheQueryPathReachesDaddyboundOnlyThroughTheObserver(t *testing.T) {
	graph, err := importGraph()
	if err != nil {
		t.Fatalf("reading the import graph: %v", err)
	}

	const (
		daddybound = modulePath + "/internal/daddybound"
		observe    = daddybound + "/observe"
		engine     = daddybound + "/dnssec"
	)

	// Packages that decide or deliver an answer and must stay entirely clear
	// of the validator.
	sealed := []string{
		modulePath + "/internal/resolver",
		modulePath + "/internal/policy",
		modulePath + "/internal/blocklist",
		modulePath + "/internal/querylog",
		modulePath + "/internal/store",
	}
	for _, root := range sealed {
		if _, ok := graph[root]; !ok {
			t.Fatalf("root package %s is not in the graph; update this test", root)
		}
		for pkg := range graph {
			if !strings.HasPrefix(pkg, daddybound) {
				continue
			}
			if path := reaches(graph, root, pkg); path != nil {
				t.Errorf("a package that decides an answer can reach Daddybound:\n  %s",
					strings.Join(path, "\n    -> "))
			}
		}
	}

	// The parts of Daddybound that must never be near production, from
	// anywhere on the query path — dnsserver included.
	adversarial := []string{
		daddybound + "/lab",
		daddybound + "/differential",
		daddybound + "/differential/refdelv",
		daddybound + "/differential/refunbound",
		daddybound + "/netsource",
	}
	queryPath := append([]string{
		modulePath + "/internal/dnsserver",
		modulePath + "/internal/api",
	}, sealed...)
	for _, root := range queryPath {
		for _, bad := range adversarial {
			if _, ok := graph[bad]; !ok {
				continue // build-tagged out of this graph; nothing to check
			}
			if path := reaches(graph, root, bad); path != nil {
				t.Errorf("the query path can reach a laboratory package:\n  %s",
					strings.Join(path, "\n    -> "))
			}
		}
	}

	// The door is exactly two packages wide.
	allowed := map[string]bool{observe: true, engine: true}
	for pkg := range graph {
		if !strings.HasPrefix(pkg, daddybound) || allowed[pkg] {
			continue
		}
		if path := reaches(graph, modulePath+"/internal/dnsserver", pkg); path != nil {
			t.Errorf("dnsserver reaches a Daddybound package outside the observer seam:\n  %s",
				strings.Join(path, "\n    -> "))
		}
	}

	// And the door exists: a test that passed because nothing imports
	// anything would be worthless.
	if path := reaches(graph, modulePath+"/internal/dnsserver", observe); path == nil {
		t.Fatal("dnsserver does not reach the observer at all; this test is checking nothing")
	}
}

// Daddybound must also not reach back into the resolver. A validation engine
// that could read the blocklist, the store or the query log would be one
// whose verdicts depended on deployment state, and a verdict that depends on
// deployment state cannot be reproduced from a recorded trace.
func TestDaddyboundDoesNotReachIntoTheResolver(t *testing.T) {
	graph, err := importGraph()
	if err != nil {
		t.Fatalf("reading the import graph: %v", err)
	}

	forbidden := []string{
		modulePath + "/internal/store",
		modulePath + "/internal/config",
		modulePath + "/internal/resolver",
		modulePath + "/internal/dnsserver",
		modulePath + "/internal/policy",
		modulePath + "/internal/blocklist",
		modulePath + "/internal/querylog",
		modulePath + "/internal/api",
		modulePath + "/internal/secrets",
	}

	var daddyboundPkgs []string
	for pkg := range graph {
		if strings.HasPrefix(pkg, modulePath+"/internal/daddybound") {
			daddyboundPkgs = append(daddyboundPkgs, pkg)
		}
	}
	if len(daddyboundPkgs) == 0 {
		t.Fatal("no daddybound packages found; update this test")
	}

	for _, pkg := range daddyboundPkgs {
		for _, bad := range forbidden {
			if path := reaches(graph, pkg, bad); path != nil {
				t.Errorf("Daddybound reaches deployment state:\n  %s", strings.Join(path, "\n    -> "))
			}
		}
	}
}

// importGraph maps each in-repo package to the in-repo packages it imports.
//
// Test files are excluded deliberately. A test may import anything it likes —
// the differential harness reads the lab, and this file reads the whole tree
// — and the property under test is about what the shipped binary can link,
// not about what a test can see.
func importGraph() (map[string][]string, error) {
	graph := make(map[string][]string)

	for _, root := range []string{"internal", "cmd"} {
		dir := filepath.Join("..", "..", root)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() || strings.Contains(path, "/testdata") {
				return nil
			}

			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			pkg := modulePath + "/" + filepath.ToSlash(strings.TrimPrefix(path, "../../"))
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
					continue
				}
				imports, err := importsOf(filepath.Join(path, name))
				if err != nil {
					return err
				}
				for _, imp := range imports {
					if strings.HasPrefix(imp, modulePath+"/") && !contains(graph[pkg], imp) {
						graph[pkg] = append(graph[pkg], imp)
					}
				}
				if _, ok := graph[pkg]; !ok {
					graph[pkg] = nil
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return graph, nil
}

// importsOf reads a file's imports ignoring build constraints.
//
// Ignoring them is the point. The libunbound adapter is excluded from every
// shipped build by its tags, and this test still must not let the query path
// import it: a property that holds only because of a build tag is one flag
// away from not holding.
func importsOf(path string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, spec := range file.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// reaches returns the import path from → target, or nil.
func reaches(graph map[string][]string, from, target string) []string {
	type node struct {
		pkg  string
		path []string
	}
	seen := map[string]bool{from: true}
	queue := []node{{from, []string{from}}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range graph[cur.pkg] {
			if next == target || strings.HasPrefix(next, target+"/") {
				return append(append([]string{}, cur.path...), next)
			}
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, node{next, append(append([]string{}, cur.path...), next)})
		}
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
