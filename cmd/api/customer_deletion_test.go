package main

import (
	"context"
	"testing"
)

func TestCustomerDeletionPendingDistinguishesDisabledAndUnavailableStore(t *testing.T) {
	if callback := customerDeletionPending(nil, false); callback != nil {
		t.Fatal("unconfigured lifecycle changed signup behavior")
	}
	callback := customerDeletionPending(nil, true)
	if callback == nil {
		t.Fatal("configured but unavailable store became observed absence")
	}
	if pending, err := callback(context.Background(), "123"); err == nil || pending {
		t.Fatalf("unavailable store must be unknown: %v %v", pending, err)
	}
}

func TestCustomerTenantDeletionProbePreservesUnknownStore(t *testing.T) {
	if customerTenantDeletionPending(nil, false) != nil {
		t.Fatal("unconfigured probe changed creation")
	}
	probe := customerTenantDeletionPending(nil, true)
	if pending, err := probe(context.Background(), "acme"); err == nil || pending {
		t.Fatalf("missing store became clear: %v %v", pending, err)
	}
}

func TestCustomerDeletionArgoOwnershipDoesNotCaptureSiblingNames(t *testing.T) {
	for _, tc := range []struct {
		name, namespace string
		remains         bool
	}{
		{"acme-corp-web", "acme-corp", false},
		{"acme-corp-preview-web", "acme-corp-preview", false},
		{"tenant-acme", "argocd", true},
		{"renamed-service", "acme", true},
		{"renamed-preview-service", "acme-preview", true},
	} {
		if got := customerDeletionAppRemains("acme", tc.name, tc.namespace); got != tc.remains {
			t.Errorf("%s in %s: got %v want %v", tc.name, tc.namespace, got, tc.remains)
		}
	}
}
