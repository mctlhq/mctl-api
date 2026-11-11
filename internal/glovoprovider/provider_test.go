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

package glovoprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
	"github.com/mctlhq/mctl-api/internal/glovoprovider/reorder"
	"github.com/mctlhq/mctl-api/internal/glovoprovider/synthetic"
)

func TestErrorKindsStayDistinct(t *testing.T) {
	cause := errors.New("upstream said: secret-session-detail")
	un := gp.Unobserved(gp.OpCart, cause)
	ab := gp.Absent(gp.OpOrder)
	if !errors.Is(un, gp.ErrUnobserved) || errors.Is(un, gp.ErrAbsent) {
		t.Fatalf("unobserved kind wrong: %v", un)
	}
	if !errors.Is(ab, gp.ErrAbsent) || errors.Is(ab, gp.ErrUnobserved) {
		t.Fatalf("absent kind wrong: %v", ab)
	}
	if !errors.Is(un, cause) {
		t.Fatal("cause must stay reachable through errors.Is")
	}
	if strings.Contains(un.Error(), "secret-session-detail") {
		t.Fatalf("error text leaks the provider cause: %q", un.Error())
	}
	if !errors.Is(gp.Unobserved(gp.OpCart, context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("deadline must stay reachable")
	}
}

func TestCartFingerprint(t *testing.T) {
	base := gp.CartSnapshot{StoreID: "st_a", Currency: "EUR", Lines: []gp.CartLine{
		{ProductID: "prd_a", Quantity: 1, UnitPriceMinor: 100, Options: []gp.CartOption{{GroupID: "g2", OptionID: "o2"}, {GroupID: "g1", OptionID: "o1"}}},
		{ProductID: "prd_b", Quantity: 2, UnitPriceMinor: 50},
	}}
	reordered := gp.CartSnapshot{StoreID: "st_a", Currency: "EUR", Version: "v-other", Lines: []gp.CartLine{
		{ProductID: "prd_b", Quantity: 2, UnitPriceMinor: 50},
		{ProductID: "prd_a", Quantity: 1, UnitPriceMinor: 100, Options: []gp.CartOption{{GroupID: "g1", OptionID: "o1"}, {GroupID: "g2", OptionID: "o2"}}},
	}}
	a, err := gp.CartFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := gp.CartFingerprint(reordered)
	if a != b || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("order or version changed the fingerprint: %s vs %s", a, b)
	}
	// Two lines with the same product and options sort by quantity and
	// price, so their read order cannot change the fingerprint.
	dupA := gp.CartSnapshot{StoreID: "st_a", Currency: "EUR", Lines: []gp.CartLine{
		{ProductID: "prd_a", Quantity: 1, UnitPriceMinor: 100}, {ProductID: "prd_a", Quantity: 2, UnitPriceMinor: 90}}}
	dupB := gp.CartSnapshot{StoreID: "st_a", Currency: "EUR", Lines: []gp.CartLine{dupA.Lines[1], dupA.Lines[0]}}
	fa, _ := gp.CartFingerprint(dupA)
	fb, _ := gp.CartFingerprint(dupB)
	if fa != fb {
		t.Fatal("duplicate-product lines: order changed the fingerprint")
	}
	mutations := map[string]func(*gp.CartSnapshot){
		"quantity": func(c *gp.CartSnapshot) { c.Lines[1].Quantity = 3 },
		"price":    func(c *gp.CartSnapshot) { c.Lines[1].UnitPriceMinor = 51 },
		"option":   func(c *gp.CartSnapshot) { c.Lines[0].Options = c.Lines[0].Options[:1] },
		"store":    func(c *gp.CartSnapshot) { c.StoreID = "st_b" },
		"empty":    func(c *gp.CartSnapshot) { c.Lines = []gp.CartLine{} },
	}
	for name, mut := range mutations {
		c := base
		c.Lines = append([]gp.CartLine(nil), base.Lines...)
		mut(&c)
		got, _ := gp.CartFingerprint(c)
		if got == a {
			t.Errorf("%s: fingerprint did not change", name)
		}
	}
}

func TestWriteProtocolTransitions(t *testing.T) {
	cases := []struct {
		from, to gp.WriteState
		ok       bool
	}{
		{gp.WritePlanned, gp.WriteCartReread, true},
		{gp.WritePlanned, gp.WriteInFlight, false},    // never write without a reread
		{gp.WriteCartReread, gp.WriteInFlight, false}, // never write before the grant check
		{gp.WriteCartReread, gp.WriteGrantVerified, true},
		{gp.WriteCartReread, gp.WritePreconditionFailed, true},
		{gp.WriteGrantVerified, gp.WriteInFlight, true},
		{gp.WriteInFlight, gp.WriteReconciled, false}, // never reconcile without a reread
		{gp.WriteInFlight, gp.WriteReconcileUnknown, true},
		{gp.WriteInFlight, gp.WriteVerifyReread, true},
		{gp.WriteVerifyReread, gp.WriteReconciled, true},
		{gp.WriteReconcileUnknown, gp.WriteInFlight, false}, // no blind retry
		{gp.WriteReconcileUnknown, gp.WriteGrantVerified, false},
		{gp.WriteReconcileUnknown, gp.WriteVerifyReread, true},
		{gp.WriteReconciled, gp.WriteInFlight, false},
		{gp.WritePreconditionFailed, gp.WriteCartReread, false},
		{gp.WriteMismatch, gp.WriteInFlight, false},
	}
	for _, c := range cases {
		if got := gp.CanTransition(c.from, c.to); got != c.ok {
			t.Errorf("%s -> %s = %v, want %v", c.from, c.to, got, c.ok)
		}
	}
}

func TestApplyCartRequestValidate(t *testing.T) {
	good := gp.ApplyCartRequest{ExpectedCartFingerprint: "sha256:aa", IntentDigest: "sha256:bb", ApprovalGrantRef: "aar_x",
		StoreID: "st_a", Lines: []gp.CartLine{{ProductID: "prd_a", Quantity: 1}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*gp.ApplyCartRequest){
		"no expected cart": func(r *gp.ApplyCartRequest) { r.ExpectedCartFingerprint = "" },
		"no digest":        func(r *gp.ApplyCartRequest) { r.IntentDigest = "abc" },
		"no grant":         func(r *gp.ApplyCartRequest) { r.ApprovalGrantRef = "" },
		"no lines":         func(r *gp.ApplyCartRequest) { r.Lines = nil },
	} {
		r := good
		mut(&r)
		if err := r.Validate(); !errors.Is(err, gp.ErrInvalidRequest) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// bannedField matches a field name or JSON key that would carry personal or
// session data. Tokens are matched on word boundaries of the snake_case form.
var bannedField = regexp.MustCompile(`(^|_)(address|addr|street|zip|postcode|postal|phone|mobile|email|mail|customer|courier|rider|lat|lng|lon|latitude|longitude|coords?|geo|first|last|full|surname|birth|dob|card|iban|token|session|cookie|password|secret|user|account)(_|$)`)

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func walkType(t *testing.T, typ reflect.Type, path string, seen map[reflect.Type]bool) {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		for _, name := range []string{snake(f.Name), tag} {
			if name != "" && bannedField.MatchString(name) {
				t.Errorf("%s.%s (json %q) looks like a personal or session field", path, f.Name, tag)
			}
		}
		walkType(t, f.Type, path+"."+f.Name, seen)
	}
}

// TestTypesCarryNoPersonalFields proves the minimized read model, the intent
// and the fixture types have no field for an address, a phone, an email, a
// customer identity, coordinates or session material.
func TestTypesCarryNoPersonalFields(t *testing.T) {
	seen := map[reflect.Type]bool{}
	for _, v := range []any{
		gp.LocationContext{}, gp.StoreQuery{}, gp.StoreSummary{}, gp.Catalog{}, gp.Product{}, gp.HistoryQuery{},
		gp.OrderSummary{}, gp.HistoricalOrder{}, gp.CartSnapshot{}, gp.ApplyCartRequest{}, gp.ApplyCartResult{},
		reorder.Intent{}, reorder.Result{}, synthetic.Fixture{}, synthetic.Scenario{},
	} {
		typ := reflect.TypeOf(v)
		walkType(t, typ, typ.Name(), seen)
	}
	if !bannedField.MatchString(snake("DeliveryAddress")) || !bannedField.MatchString("customer_id") || !bannedField.MatchString("lat") {
		t.Fatal("the banned-field pattern no longer detects personal fields")
	}
}

var (
	emailLike = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneLike = regexp.MustCompile(`\+\d{6,}|\d{9,}`)
)

func scanJSON(t *testing.T, file string, v any, path string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if bannedField.MatchString(k) {
				t.Errorf("%s: key %s.%s looks personal", file, path, k)
			}
			scanJSON(t, file, val, path+"."+k)
		}
	case []any:
		for _, val := range x {
			scanJSON(t, file, val, path+"[]")
		}
	case string:
		if emailLike.MatchString(x) || phoneLike.MatchString(x) {
			t.Errorf("%s: value at %s looks like an email or phone", file, path)
		}
	}
}

// TestFixturesCarryNoPersonalData scans every fixture JSON key and string.
func TestFixturesCarryNoPersonalData(t *testing.T) {
	n := 0
	err := filepath.WalkDir("synthetic/testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		raw, err := os.ReadFile(p) //nolint:gosec // path comes from WalkDir over the package testdata
		if err != nil {
			return err
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		scanJSON(t, p, v, "$")
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("scanned %d fixture files; the scan is not looking at the fixtures", n)
	}
}
