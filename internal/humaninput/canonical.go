package humaninput

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

// canonicalJSON reproduces mctl-agents' `_canonical_json` byte for byte:
//
//	json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
//
// Go's encoding/json cannot be used for this. It escapes <, > and & (unless
// told not to), escapes U+2028/U+2029, and writes non-ASCII as raw UTF-8,
// while Python's default ensure_ascii=True writes every non-ASCII code point
// as a lowercase \uXXXX escape (astral ones as a surrogate pair). A single
// differing byte changes request_hash, so the hash of any request with a
// non-ASCII question would never verify.
//
// Supported values are exactly what the request payload contains: nil,
// bool, int, string, []any, []string and map[string]any.
func canonicalJSON(v any) ([]byte, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeCanonical(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(t))
	case string:
		writePyString(b, t)
	case []string:
		b.WriteByte('[')
		for i, s := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writePyString(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Python sorts str keys by code point; for valid UTF-8, byte order
		// is the same order.
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writePyString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported value of type %T", v)
	}
	return nil
}

// writePyString is json.dumps' ensure_ascii string encoding: the short
// escapes for " \ \n \r \t \b \f, and \uXXXX (lowercase hex) for every other
// code point outside printable ASCII -- including DEL -- with astral code
// points as UTF-16 surrogate pairs.
func writePyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				b.WriteRune(r)
			case r == utf8.RuneError:
				// Invalid UTF-8 cannot come out of a JSON document Go
				// decoded; encode the replacement character like Python.
				fmt.Fprintf(b, `\u%04x`, r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}

// hashBytes is mctl-agents' `_hash_bytes`: "sha256:" + lowercase hex.
func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// pyIsSpace is Python's str.isspace, which is what both re's `\s` (on str)
// and str.strip() use: Go's unicode.IsSpace plus the four ASCII information
// separators U+001C..U+001F, which Python counts as whitespace and Go does
// not.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pyNormalizeQuestion is question_hash_for's normalisation:
// _WHITESPACE_RE.sub(" ", q).strip().casefold(). cases.Fold is full Unicode
// case folding, which is what str.casefold implements (e.g. "ß" -> "ss").
func pyNormalizeQuestion(q string) string {
	var b strings.Builder
	inSpace := false
	for _, r := range q {
		if pyIsSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteRune(r)
	}
	return cases.Fold().String(strings.TrimFunc(b.String(), pyIsSpace))
}

// HashBytes is hashBytes for callers outside this package.
func HashBytes(raw []byte) string { return hashBytes(raw) }
