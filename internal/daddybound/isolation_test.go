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

// Daddybound must not be able to answer a query. That is a claim about the
// import graph, so it is checked as one.
//
// The engine generates keys, signs zones, and reaches verdicts it is not yet
// entitled to enforce. Every document in this repository says it enforces
// nothing; this test is what makes that a property of the build rather than a
// promise in a README. A stray import from the query path would make it
// possible to wire Daddybound into a real answer, and the first sign would be
// a resolver acting on a verdict from an engine explicitly labelled
// experimental.
func TestTheQueryPathCannotReachDaddybound(t *testing.T) {
	graph, err := importGraph()
	if err != nil {
		t.Fatalf("reading the import graph: %v", err)
	}

	// The packages that decide or deliver an answer to a client.
	roots := []string{
		modulePath + "/internal/resolver",
		modulePath + "/internal/dnsserver",
		modulePath + "/internal/policy",
		modulePath + "/internal/blocklist",
		modulePath + "/internal/api",
		modulePath + "/internal/querylog",
		modulePath + "/internal/store",
	}

	for _, root := range roots {
		if _, ok := graph[root]; !ok {
			// A renamed or removed package would otherwise make this test
			// pass by checking nothing.
			t.Fatalf("root package %s is not in the graph; update this test", root)
		}
		if path := reaches(graph, root, modulePath+"/internal/daddybound"); path != nil {
			t.Errorf("the query path can reach Daddybound:\n  %s", strings.Join(path, "\n    -> "))
		}
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
