package audit

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

// WriteFailures counts audit rows that could not be persisted. The operation
// label is "support.request" or "other", to keep cardinality bounded.
var WriteFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_audit_write_failures_total",
	Help: "Audit rows that could not be written to PostgreSQL, by operation (support.request, other).",
}, []string{"operation"})

func init() {
	prometheus.MustRegister(WriteFailures)
	// Export both series at 0 from start-up, so the first failure is an
	// increase an alert can see rather than a series appearing at 1.
	WriteFailures.WithLabelValues(OperationSupportRequest)
	WriteFailures.WithLabelValues("other")
}

// recordWriteFailure counts and logs a failed audit write.
func recordWriteFailure(entry Entry, err error) {
	op := "other"
	if entry.Operation == OperationSupportRequest {
		op = OperationSupportRequest
	}
	WriteFailures.WithLabelValues(op).Inc()
	slog.Error("audit postgres: insert failed", "operation", entry.Operation, "request_id", entry.RequestID, "error", err)
}
