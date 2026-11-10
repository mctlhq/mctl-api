package main

import (
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

func lookupOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestConfigureGlovoControlIsDark(t *testing.T) {
	w := &auth.GlovoControlWorkerConfig{Tenants: []string{"acme"}}
	for name, c := range map[string]struct {
		env    map[string]string
		worker *auth.GlovoControlWorkerConfig
	}{
		"unset":         {nil, w},
		"false":         {map[string]string{"MCTL_GLOVO_CONTROL_ENABLED": "false"}, w},
		"no worker":     {map[string]string{"MCTL_GLOVO_CONTROL_ENABLED": "true"}, nil},
		"empty tenants": {map[string]string{"MCTL_GLOVO_CONTROL_ENABLED": "true"}, &auth.GlovoControlWorkerConfig{}},
	} {
		got, err := configureGlovoControl(lookupOf(c.env), c.worker)
		if err != nil || got != nil {
			t.Errorf("%s: %v %v, want unmounted", name, got, err)
		}
	}
	if _, err := configureGlovoControl(lookupOf(map[string]string{"MCTL_GLOVO_CONTROL_ENABLED": "yes"}), w); err == nil {
		t.Error("a malformed flag was accepted")
	}
	got, err := configureGlovoControl(lookupOf(map[string]string{"MCTL_GLOVO_CONTROL_ENABLED": "true"}), w)
	if err != nil || got == nil {
		t.Fatalf("enabled: %v %v", got, err)
	}
	if got.Open != glovo.ControlDefault.Open {
		t.Error("Open is not the build gate")
	}
	if got.Dispatcher != nil {
		t.Error("a dispatcher was attached without its stores")
	}
	if len(got.Tenants) != 1 || got.Tenants[0] != "acme" {
		t.Errorf("tenants %v", got.Tenants)
	}
	got.Tenants[0] = "x"
	if w.Tenants[0] != "acme" {
		t.Error("the worker config was aliased")
	}
}

func TestGlovoFencePreconditionsNeedAllSix(t *testing.T) {
	full := glovoFencePreconditions{true, true, true, true, true, true}
	if !full.All() {
		t.Fatal("all six true must pass")
	}
	for i := 0; i < 6; i++ {
		p := []bool{true, true, true, true, true, true}
		p[i] = false
		got := glovoFencePreconditions{p[0], p[1], p[2], p[3], p[4], p[5]}
		if got.All() {
			t.Errorf("precondition %d false still passed", i+1)
		}
	}
	if (glovoFencePreconditions{}).All() {
		t.Error("the zero value passed")
	}
}
