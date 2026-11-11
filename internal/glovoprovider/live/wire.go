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

package live

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	errDrift = ErrSchemaDrift
	reID     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reMoney  = regexp.MustCompile(`^(-?)(\d{1,9})(?:[.,](\d{1,2}))?$`)
)

// validID reports whether s is safe to use as a path segment or an id.
func validID(s string) bool { return reID.MatchString(s) }

// flexString decodes a JSON string or integer into a string. Anything else
// (object, bool, array, float) is an error, so a type change is drift.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*f = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	if _, err := strconv.ParseInt(string(b), 10, 64); err != nil {
		return errDrift
	}
	*f = flexString(b)
	return nil
}

// flexID is a flexString that also remembers the original JSON token, so a
// numeric id is written back as a number and a string id as a string.
type flexID struct{ raw json.RawMessage }

func (f *flexID) UnmarshalJSON(b []byte) error {
	var s flexString
	if err := s.UnmarshalJSON(b); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		f.raw = nil
		return nil
	}
	f.raw = append(json.RawMessage(nil), bytes.TrimSpace(b)...)
	return nil
}

func (f flexID) MarshalJSON() ([]byte, error) {
	if len(f.raw) == 0 {
		return []byte("null"), nil
	}
	return f.raw, nil
}

// s returns the id as a plain string ("" when absent).
func (f flexID) s() string {
	var s flexString
	if len(f.raw) == 0 || s.UnmarshalJSON(f.raw) != nil {
		return ""
	}
	return string(s)
}

// parseMoney converts a JSON money value to minor units without floating
// point. It accepts a number or a string in major units ("3.00", "3,00 EUR",
// "3.00 EUR"). More than two fraction digits, thousands separators, an
// unknown shape or a currency other than want is an error.
func parseMoney(raw json.RawMessage, want string) (int64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, errDrift
	}
	var s string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, errDrift
		}
	} else {
		s = string(raw)
		if strings.ContainsAny(s, "eE") {
			return 0, errDrift
		}
	}
	s = strings.ReplaceAll(s, " ", " ")
	s = strings.TrimSpace(strings.Replace(s, "€", " EUR ", 1))
	fields := strings.Fields(s)
	var num string
	switch len(fields) {
	case 1:
		num = fields[0]
	case 2:
		code, n := fields[1], fields[0]
		if reCurrency.MatchString(fields[0]) {
			code, n = fields[0], fields[1]
		}
		if !reCurrency.MatchString(code) || code != want {
			return 0, errDrift
		}
		num = n
	default:
		return 0, errDrift
	}
	m := reMoney.FindStringSubmatch(num)
	if m == nil {
		return 0, errDrift
	}
	major, _ := strconv.ParseInt(m[2], 10, 64)
	frac := m[3]
	for len(frac) < 2 {
		frac += "0"
	}
	minor, _ := strconv.ParseInt(frac, 10, 64)
	v := major*100 + minor
	if m[1] == "-" {
		v = -v
	}
	return v, nil
}

type priceInfo struct {
	Amount json.RawMessage `json:"amount"`
}

// parseTime accepts epoch seconds, epoch milliseconds or an RFC 3339 string.
func parseTime(raw json.RawMessage) (time.Time, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return time.Time{}, false
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return time.Time{}, false
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			return epoch(n), true
		}
		t, err := time.Parse(time.RFC3339, s)
		return t.UTC(), err == nil
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return epoch(n), true
}

func epoch(n int64) time.Time {
	if n < 10_000_000_000 {
		return time.Unix(n, 0).UTC()
	}
	return time.UnixMilli(n).UTC()
}

// parseQuantity parses a positive integer given as a number or a string.
func parseQuantity(raw json.RawMessage) (int64, error) {
	raw = bytes.TrimSpace(raw)
	s := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, errDrift
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 1 || n > 10_000 {
		return 0, errDrift
	}
	return n, nil
}
