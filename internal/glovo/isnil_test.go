package glovo

import "testing"

type nilProbe struct{}

func TestIsNilSeesTypedNils(t *testing.T) {
	var p *nilProbe
	eqNil := func(v any) bool { return v == nil }
	if eqNil(p) {
		t.Fatal("premise: a typed nil in an interface is not == nil")
	}
	var f func()
	var m map[string]int
	var s []int
	var c chan int
	for name, v := range map[string]any{"untyped": nil, "ptr": p, "func": f, "map": m, "slice": s, "chan": c} {
		if !IsNil(v) {
			t.Errorf("%s: IsNil = false", name)
		}
	}
	for name, v := range map[string]any{"ptr": &nilProbe{}, "int": 0, "string": "", "struct": nilProbe{}, "map": map[string]int{}} {
		if IsNil(v) {
			t.Errorf("%s: IsNil = true for a present value", name)
		}
	}
}
