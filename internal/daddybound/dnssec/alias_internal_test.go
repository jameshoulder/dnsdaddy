package dnssec

import "testing"

// The chain lattice, stated as a table rather than derived from chainRank.
//
// Deriving the expectation from the same ranking the implementation uses
// would test that a function equals itself. These are written out, so
// renumbering chainRank breaks them.
func TestWeakestIsTheChainLattice(t *testing.T) {
	all := []ValidationStatus{StatusSecure, StatusInsecure, StatusIndeterminate, StatusBogus}

	for _, tc := range []struct {
		a, b, want ValidationStatus
	}{
		{StatusSecure, StatusSecure, StatusSecure},

		// Insecure beats Secure: a chain through an authenticated unsigned
		// zone is not authenticated, however well signed the rest is.
		{StatusSecure, StatusInsecure, StatusInsecure},
		{StatusInsecure, StatusSecure, StatusInsecure},

		// Indeterminate beats Insecure: Insecure is a proof that the data is
		// unsigned, and a chain containing a link nobody could evaluate has
		// no such proof.
		{StatusInsecure, StatusIndeterminate, StatusIndeterminate},
		{StatusIndeterminate, StatusInsecure, StatusIndeterminate},
		{StatusSecure, StatusIndeterminate, StatusIndeterminate},

		// Bogus beats everything. One tampered link is not mitigated by the
		// rest of the chain being fine.
		{StatusBogus, StatusSecure, StatusBogus},
		{StatusSecure, StatusBogus, StatusBogus},
		{StatusBogus, StatusInsecure, StatusBogus},
		{StatusBogus, StatusIndeterminate, StatusBogus},
	} {
		if got := weakest(tc.a, tc.b); got != tc.want {
			t.Errorf("weakest(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}

	// Secure is the identity, which is what makes StatusSecure a safe value
	// to start a chain accumulator at. If it were not, a one-hop answer would
	// come out weaker than the hop itself.
	for _, s := range all {
		if got := weakest(StatusSecure, s); got != s {
			t.Errorf("weakest(secure, %s) = %s; secure must be the identity", s, got)
		}
	}

	// Commutative, so the verdict cannot depend on which hop the accumulator
	// happened to see first, and idempotent, so a repeated status cannot
	// drift.
	for _, a := range all {
		if got := weakest(a, a); got != a {
			t.Errorf("weakest(%s, %s) = %s; must be idempotent", a, a, got)
		}
		for _, b := range all {
			if weakest(a, b) != weakest(b, a) {
				t.Errorf("weakest is not commutative at (%s, %s)", a, b)
			}
		}
	}

	// Associative, so a chain's verdict does not depend on how the hops were
	// grouped. chase folds left; nothing should hinge on that.
	for _, a := range all {
		for _, b := range all {
			for _, c := range all {
				if weakest(weakest(a, b), c) != weakest(a, weakest(b, c)) {
					t.Errorf("weakest is not associative at (%s, %s, %s)", a, b, c)
				}
			}
		}
	}

	// Monotonic: adding a hop can only weaken a chain, never strengthen it.
	// This is the property that stops a signed terminal RRset rescuing an
	// unauthenticated redirection, and it is the whole reason the accumulator
	// exists rather than the last hop's verdict being returned directly.
	for _, a := range all {
		for _, b := range all {
			if chainRank(weakest(a, b)) < chainRank(a) {
				t.Errorf("weakest(%s, %s) is stronger than %s", a, b, a)
			}
		}
	}
}

// chainRank must be a total order with no ties, or weakest stops being a
// function of the pair: two statuses at one rank would make the result depend
// on argument order, which is exactly what the commutativity above forbids.
func TestChainRankHasNoTies(t *testing.T) {
	seen := map[int]ValidationStatus{}
	for _, s := range []ValidationStatus{StatusSecure, StatusInsecure, StatusIndeterminate, StatusBogus} {
		r := chainRank(s)
		if other, dup := seen[r]; dup {
			t.Errorf("%s and %s share rank %d", other, s, r)
		}
		seen[r] = s
	}
}
