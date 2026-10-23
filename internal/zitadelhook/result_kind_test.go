package zitadelhook

import "testing"

// Every constructor must stamp a Kind: the metric in internal/api keys on
// it, and an empty label would hide refusals behind an unlabelled series.
func TestResultKinds(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		want string
	}{
		{"pass", pass("x"), KindPass},
		{"refuse", refuse(403, "x", "m"), KindRefuse},
		{"failure", failure("x"), KindFailure},
		{"replace", replace("x", map[string]string{"a": "b"}), KindReplace},
	}
	for _, c := range cases {
		if c.res.Kind != c.want {
			t.Errorf("%s: Kind = %q, want %q", c.name, c.res.Kind, c.want)
		}
	}
}
