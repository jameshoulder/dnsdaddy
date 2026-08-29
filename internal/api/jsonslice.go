package api

// nonNilSlice returns s, or an empty slice when s is nil.
//
// encoding/json renders a nil slice as null and an empty slice as []. Every
// list this API returns is documented in openapi.yaml as an array, and the
// dashboard iterates them without guarding — so a nil slice reaching the wire
// is a broken page, not a cosmetic difference. Handlers that build a list by
// appending should pass it through this before responding, because "nothing
// yet" is the normal state of a fresh install rather than an edge case.
func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
