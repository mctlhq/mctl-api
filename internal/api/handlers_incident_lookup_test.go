package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/alerts"
)

func TestWriteIncidentLookupError_StatusMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"too short", alerts.ErrPrefixTooShort, http.StatusBadRequest},
		{"not found", alerts.ErrNotFound, http.StatusNotFound},
		{"ambiguous", alerts.ErrAmbiguousPrefix, http.StatusConflict},
		{"wrapped not found", errors.Join(errors.New("ctx"), alerts.ErrNotFound), http.StatusNotFound},
		{"other", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeIncidentLookupError(rec, "abc12345", tc.err)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
