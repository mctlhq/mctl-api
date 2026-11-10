// Copyright 2026 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package jcs is the one RFC 8785 (JSON Canonicalization Scheme)
// implementation of mctl-api and the raw-bytes pre-check of the #1059 bridge
// contract. It depends on nothing else in mctl-api: internal/bridge and
// internal/glovo import it, never the reverse.
package jcs

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Limits of Precheck. The basket and read documents nest to depth 6.
const (
	MaxDepth = 32
	MaxSize  = 1 << 20
	maxSafe  = 9007199254740991 // 2^53 - 1
)

// Reasons returned in the error text, matching the #1059 must-reject codes.
var (
	ErrDuplicateKey  = errors.New("jcs: duplicate_key")
	ErrEscapedKey    = errors.New("jcs: escaped_key")
	ErrLoneSurrogate = errors.New("jcs: lone_surrogate")
	ErrNonFinite     = errors.New("jcs: non_finite")
	ErrNumberRange   = errors.New("jcs: number_range")
	ErrNonInteger    = errors.New("jcs: non_integer_token")
	ErrBOM           = errors.New("jcs: bom")
	ErrTrailingBytes = errors.New("jcs: trailing_bytes")
	ErrNotObject     = errors.New("jcs: not_object")
	ErrControlChar   = errors.New("jcs: control_char")
	ErrTooDeep       = errors.New("jcs: too_deep")
	ErrTooLarge      = errors.New("jcs: too_large")
	ErrSyntax        = errors.New("jcs: syntax")
	ErrInvalidUTF8   = errors.New("jcs: invalid_utf8")
)

// Precheck is the token-level raw-bytes pre-check that runs before any schema
// validation: no BOM, a single root object, no trailing bytes, no duplicate
// key (an object key is never written with an escape, so a duplicate cannot
// hide behind one), no raw control character, no lone surrogate, no
// non-finite or out-of-range number, no integer beyond 2^53-1, depth at most
// MaxDepth and size at most MaxSize.
func Precheck(raw []byte) error {
	if len(raw) > MaxSize {
		return ErrTooLarge
	}
	_, err := parse(raw, true)
	return err
}

// PrecheckIntegers is Precheck plus a refusal of every number written with a
// fraction, an exponent or a negative zero. A document whose numbers are all
// integers (the approval basket) uses it.
func PrecheckIntegers(raw []byte) error {
	if err := Precheck(raw); err != nil {
		return err
	}
	_, err := parse(raw, true, withIntegers)
	return err
}

// Canonicalize returns the RFC 8785 form of one JSON value. It refuses
// duplicate keys, a lone surrogate, invalid UTF-8, a number outside the
// float64 range and a BOM or trailing bytes. Unlike Precheck it accepts any
// root value and escaped keys.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := parse(raw, false)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes(), nil
}

type node struct {
	kind  byte // 'o' object, 'a' array, 's' string, 'n' number, 'l' literal
	str   string
	num   float64
	lit   string
	keys  []string
	items []*node // array items, or object values parallel to keys
}

type option int

const withIntegers option = 1

type parser struct {
	b        []byte
	i        int
	strict   bool
	integers bool
}

func parse(raw []byte, strict bool, opts ...option) (*node, error) {
	p := &parser{b: raw, strict: strict}
	for _, o := range opts {
		if o == withIntegers {
			p.integers = true
		}
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, ErrBOM
	}
	p.ws()
	if strict && (p.i >= len(p.b) || p.b[p.i] != '{') {
		return nil, ErrNotObject
	}
	v, err := p.value(1)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, ErrTrailingBytes
	}
	return v, nil
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	if p.i >= len(p.b) {
		return nil, ErrSyntax
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str(false)
		if err != nil {
			return nil, err
		}
		return &node{kind: 's', str: s}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case c == 'N' || c == 'I':
		return nil, ErrNonFinite
	default:
		for _, l := range []string{"true", "false", "null"} {
			if bytes.HasPrefix(p.b[p.i:], []byte(l)) {
				p.i += len(l)
				return &node{kind: 'l', lit: l}, nil
			}
		}
		return nil, ErrSyntax
	}
}

func (p *parser) object(depth int) (*node, error) {
	p.i++ // {
	n := &node{kind: 'o'}
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return n, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, ErrSyntax
		}
		k, err := p.str(true)
		if err != nil {
			return nil, err
		}
		if seen[k] {
			return nil, ErrDuplicateKey
		}
		seen[k] = true
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, ErrSyntax
		}
		p.i++
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, k)
		n.items = append(n.items, v)
		p.ws()
		if p.i >= len(p.b) {
			return nil, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return n, nil
		default:
			return nil, ErrSyntax
		}
	}
}

func (p *parser) array(depth int) (*node, error) {
	p.i++ // [
	n := &node{kind: 'a'}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return n, nil
	}
	for {
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.items = append(n.items, v)
		p.ws()
		if p.i >= len(p.b) {
			return nil, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return n, nil
		default:
			return nil, ErrSyntax
		}
	}
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	v, err := strconv.ParseUint(string(b[:4]), 16, 32)
	if err != nil {
		return 0, false
	}
	for _, c := range b[:4] {
		if c == '+' || c == '-' {
			return 0, false
		}
	}
	return rune(v), true
}

// str reads one string token. In strict mode an escape inside an object key
// is refused.
func (p *parser) str(isKey bool) (string, error) {
	p.i++ // opening quote
	var out strings.Builder
	for {
		if p.i >= len(p.b) {
			return "", ErrSyntax
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return out.String(), nil
		case c < 0x20:
			return "", ErrControlChar
		case c == '\\':
			if isKey && p.strict {
				return "", ErrEscapedKey
			}
			if p.i+1 >= len(p.b) {
				return "", ErrSyntax
			}
			e := p.b[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				out.WriteByte(e)
			case 'b':
				out.WriteByte('\b')
			case 'f':
				out.WriteByte('\f')
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			case 'u':
				r, ok := hex4(p.b[p.i:])
				if !ok {
					return "", ErrSyntax
				}
				p.i += 4
				switch {
				case utf16.IsSurrogate(r) && r >= 0xDC00:
					return "", ErrLoneSurrogate
				case utf16.IsSurrogate(r):
					if p.i+6 > len(p.b) || p.b[p.i] != '\\' || p.b[p.i+1] != 'u' {
						return "", ErrLoneSurrogate
					}
					lo, ok := hex4(p.b[p.i+2:])
					if !ok || lo < 0xDC00 || lo > 0xDFFF {
						return "", ErrLoneSurrogate
					}
					p.i += 6
					out.WriteRune(utf16.DecodeRune(r, lo))
				default:
					out.WriteRune(r)
				}
			default:
				return "", ErrSyntax
			}
		default:
			r, size := utf8.DecodeRune(p.b[p.i:])
			if r == utf8.RuneError && size <= 1 {
				return "", ErrInvalidUTF8
			}
			out.Write(p.b[p.i : p.i+size])
			p.i += size
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) number() (*node, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
		if p.i < len(p.b) && p.b[p.i] == 'I' {
			return nil, ErrNonFinite
		}
	}
	if p.i >= len(p.b) || !isDigit(p.b[p.i]) {
		return nil, ErrSyntax
	}
	if p.b[p.i] == '0' {
		p.i++
	} else {
		for p.i < len(p.b) && isDigit(p.b[p.i]) {
			p.i++
		}
	}
	integer := true
	if p.i < len(p.b) && p.b[p.i] == '.' {
		integer = false
		p.i++
		if p.i >= len(p.b) || !isDigit(p.b[p.i]) {
			return nil, ErrSyntax
		}
		for p.i < len(p.b) && isDigit(p.b[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		integer = false
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.b) || !isDigit(p.b[p.i]) {
			return nil, ErrSyntax
		}
		for p.i < len(p.b) && isDigit(p.b[p.i]) {
			p.i++
		}
	}
	tok := string(p.b[start:p.i])
	if p.integers && (!integer || tok == "-0") {
		return nil, ErrNonInteger
	}
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, ErrNumberRange
	}
	if p.strict && integer {
		if v, err := strconv.ParseInt(tok, 10, 64); err != nil || v > maxSafe || v < -maxSafe {
			return nil, ErrNumberRange
		}
	}
	return &node{kind: 'n', num: f}, nil
}

// formatNumber renders f with the ECMAScript Number::toString rules of
// RFC 8785 section 3.2.2.3.
func formatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde+XX
	mant, expo, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(expo)
	k := len(digits)
	n := x + 1
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		ex := n - 1
		es := "+"
		if ex < 0 {
			es = "-"
			ex = -ex
		}
		if k == 1 {
			s = digits + "e" + es + strconv.Itoa(ex)
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ex)
		}
	}
	return sign + s
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func write(b *bytes.Buffer, n *node) {
	switch n.kind {
	case 'l':
		b.WriteString(n.lit)
	case 'n':
		b.WriteString(formatNumber(n.num))
	case 's':
		writeString(b, n.str)
	case 'a':
		b.WriteByte('[')
		for i, it := range n.items {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, it)
		}
		b.WriteByte(']')
	case 'o':
		idx := make([]int, len(n.keys))
		u16 := make([][]uint16, len(n.keys))
		for i, k := range n.keys {
			idx[i] = i
			u16[i] = utf16.Encode([]rune(k))
		}
		sort.Slice(idx, func(x, y int) bool {
			a, c := u16[idx[x]], u16[idx[y]]
			for i := 0; i < len(a) && i < len(c); i++ {
				if a[i] != c[i] {
					return a[i] < c[i]
				}
			}
			return len(a) < len(c)
		})
		b.WriteByte('{')
		for i, j := range idx {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, n.keys[j])
			b.WriteByte(':')
			write(b, n.items[j])
		}
		b.WriteByte('}')
	}
}
