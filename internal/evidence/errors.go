package evidence

import "fmt"

// ValidationError is a malformed piece of evidence, named so a caller can tell
// a bad input apart from a storage failure.
type ValidationError struct {
	Field  string
	Value  string
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Value == "" {
		return fmt.Sprintf("evidence: %s is %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("evidence: %s %q is %s", e.Field, e.Value, e.Reason)
}

func errEmpty(field string) error {
	return &ValidationError{Field: field, Reason: "required"}
}

func errInvalid(field, value string) error {
	return &ValidationError{Field: field, Value: value, Reason: "not a value this build understands"}
}
