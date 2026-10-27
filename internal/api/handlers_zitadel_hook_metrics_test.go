package api

import "testing"

func TestZitadelHookReasonLabel(t *testing.T) {
	cases := map[string]string{
		"intent_customer_create_not_allowed:123456": "intent_customer_create_not_allowed",
		"intent_no_verified_email":                  "intent_no_verified_email",
		"":                                          "",
	}
	for in, want := range cases {
		if got := zitadelHookReasonLabel(in); got != want {
			t.Errorf("zitadelHookReasonLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
