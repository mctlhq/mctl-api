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
