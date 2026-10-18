package blocklist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
)

// jsonFrame only frames bounded values; encoding/json remains responsible for
// JSON syntax and schema. No Decode/Token call can allocate an unbounded value.
type jsonFrame struct {
	r    *bufio.Reader
	ctx  context.Context
	base int
}

const maxJSONValue = 1 << 20

func (f *jsonFrame) peek() (byte, error) {
	for {
		if err := f.ctx.Err(); err != nil {
			return 0, err
		}
		b, err := f.r.Peek(1)
		if err != nil {
			return 0, err
		}
		if b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t' {
			_, _ = f.r.ReadByte()
			continue
		}
		return b[0], nil
	}
}
func (f *jsonFrame) take(want byte) error {
	b, e := f.peek()
	if e != nil {
		return e
	}
	if b != want {
		return errors.New("invalid feed JSON structure")
	}
	_, e = f.r.ReadByte()
	return e
}
func (f *jsonFrame) value() ([]byte, error) {
	if _, err := f.peek(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 256)
	depth := 0
	quoted := false
	escape := false
	for {
		if err := f.ctx.Err(); err != nil {
			return nil, err
		}
		p, err := f.r.Peek(1)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		b := p[0]
		if !quoted && depth == 0 && len(out) > 0 && (b == ',' || b == ']' || b == '}' || b == ' ' || b == '\n' || b == '\r' || b == '\t') {
			break
		}
		if len(out) >= maxJSONValue {
			return nil, feedimport.Limit("JSON value bytes")
		}
		_, _ = f.r.ReadByte()
		out = append(out, b)
		if quoted {
			if escape {
				escape = false
			} else if b == '\\' {
				escape = true
			} else if b == '"' {
				quoted = false
				if depth == 0 {
					break
				}
			}
			continue
		}
		switch b {
		case '"':
			quoted = true
		case '[', '{':
			depth++
			if depth+f.base > 64 {
				return nil, feedimport.Limit("JSON nesting")
			}
		case ']', '}':
			depth--
			if depth < 0 {
				return nil, errors.New("invalid feed JSON")
			}
			if depth == 0 {
				if !json.Valid(out) {
					return nil, errors.New("invalid feed JSON")
				}
				return out, nil
			}
		}
	}
	if !json.Valid(out) {
		return nil, errors.New("invalid or truncated feed JSON")
	}
	return out, nil
}

func parseObservatoryLimited(ctx context.Context, r io.Reader, maxRecords int, emit func(ObservatoryRecord) error) (ObservatoryResult, error) {
	var res ObservatoryResult
	f := jsonFrame{r: bufio.NewReaderSize(r, 32<<10), ctx: ctx}
	records := 0
	array := func() error {
		f.base++
		defer func() { f.base-- }()
		if err := f.take('['); err != nil {
			// Operational failures remain fatal through candidate/startup classification.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, feedimport.ErrLimit) {
				return err
			}
			return errors.New("indicators is not an array")
		}
		first := true
		for {
			b, err := f.peek()
			if err != nil {
				return err
			}
			if b == ']' {
				return f.take(']')
			}
			if !first {
				if err := f.take(','); err != nil {
					return err
				}
				b, err = f.peek()
				if err != nil {
					return err
				}
				if b == ']' {
					return errors.New("trailing JSON comma")
				}
			}
			first = false
			records++
			if records > maxRecords {
				return feedimport.Limit("records per feed")
			}
			raw, err := f.value()
			if err != nil {
				return err
			}
			rec, ok := decodeIndicator(raw)
			if !ok {
				res.Skipped++
				continue
			}
			res.Accepted++
			if emit != nil {
				if err := emit(rec); err != nil {
					return err
				}
			}
		}
	}
	b, err := f.peek()
	if err != nil {
		return res, err
	}
	if b == '[' {
		err = array()
	} else if b == '{' {
		f.base = 1
		_ = f.take('{')
		first := true
		seen := false
		for {
			b, e := f.peek()
			if e != nil {
				return res, e
			}
			if b == '}' {
				_ = f.take('}')
				break
			}
			if !first {
				if e = f.take(','); e != nil {
					return res, e
				}
				b, e = f.peek()
				if e != nil {
					return res, e
				}
				if b == '}' {
					return res, errors.New("trailing JSON comma")
				}
			}
			first = false
			raw, e := f.value()
			if e != nil {
				return res, e
			}
			var key string
			if len(raw) == 0 || raw[0] != '"' {
				return res, errors.New("invalid feed JSON key")
			}
			if e = json.Unmarshal(raw, &key); e != nil {
				return res, errors.New("invalid feed JSON key")
			}
			if e = f.take(':'); e != nil {
				return res, e
			}
			if key == "indicators" {
				if seen {
					return res, errors.New("duplicate indicators array")
				}
				seen = true
				if e = array(); e != nil {
					return res, e
				}
				continue
			}
			raw, e = f.value()
			if e != nil {
				return res, e
			}
			var s string
			_ = json.Unmarshal(raw, &s)
			if key == "source" {
				res.Source = s
			}
			if key == "generated_at" {
				if ts, e := time.Parse(time.RFC3339, s); e == nil {
					res.GeneratedAt = ts.UTC()
				}
			}
		}
		if !seen {
			return res, errors.New("feed has no indicators array; not a feed document")
		}
	} else {
		return res, errors.New("feed is not a JSON object or array")
	}
	if err != nil {
		return res, err
	}
	if _, e := f.peek(); e != io.EOF {
		if e != nil {
			return res, e
		}
		return res, errors.New("trailing feed JSON")
	}
	return res, nil
}
