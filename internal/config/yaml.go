package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// unmarshalYAML decodes YAML into cfg, rejecting unknown keys so that a typo
// in a config file surfaces at startup rather than silently taking a default.
//
// A plain yaml.Unmarshal accepts unknown fields, so "retension_days: 30" would
// have been silently ignored and the operator's retention setting would not
// have applied. dec.KnownFields(true) closes that gap.
func unmarshalYAML(b []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // an empty file is valid: every field keeps its default
		}
		return err
	}

	// A second document in the same file is almost certainly a mistake — a
	// stray "---" from a copy-paste — and would otherwise be silently ignored.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("config file contains more than one YAML document")
		}
		return err
	}
	return nil
}
