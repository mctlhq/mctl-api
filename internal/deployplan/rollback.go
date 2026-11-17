package deployplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Rollback (mctl-api#1049): a plan whose "intent" points at one production
// DeployRecord. It carries the gitops commit that deployment pushed and the
// image digest it ran, bound by the plan digest; applying it restores the
// service's values.yaml as it was at that commit through the
// rollback-revision workflow, and the health gate then requires that digest.
// Both are read from the record here, never from a caller.

// RollbackIntentKind labels the stored intent of a rollback plan.
const RollbackIntentKind = "mctl-rollback-intent/v1"

// ErrRollbackIntent is a stored rollback intent that does not parse.
var ErrRollbackIntent = errors.New("deployplan: the rollback intent is not valid")

// RollbackIntent is what a rollback plan binds.
type RollbackIntent struct {
	Kind               string `json:"kind"`
	Tenant             string `json:"tenant"`
	Service            string `json:"service"`
	TargetDeploymentID string `json:"target_deployment_id"`
	TargetCommit       string `json:"target_commit"`
	ExpectedDigest     string `json:"expected_digest"`
}

func (i RollbackIntent) validate() error {
	switch {
	case i.Kind != RollbackIntentKind:
		return fmt.Errorf("%w: kind", ErrRollbackIntent)
	case i.Tenant == "" || i.Service == "":
		return fmt.Errorf("%w: tenant and service", ErrRollbackIntent)
	case !depIDRE.MatchString(i.TargetDeploymentID):
		return fmt.Errorf("%w: target_deployment_id", ErrRollbackIntent)
	case !ValidCommitSHA(i.TargetCommit):
		return fmt.Errorf("%w: target_commit", ErrRollbackIntent)
	case !ValidImageDigest(i.ExpectedDigest):
		return fmt.Errorf("%w: expected_digest", ErrRollbackIntent)
	}
	return nil
}

// Canonical is the stored, digested form.
func (i RollbackIntent) Canonical() (string, error) {
	i.Kind = RollbackIntentKind
	if err := i.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRollbackIntent, err)
	}
	return string(b), nil
}

// ParseRollbackIntent reads a stored rollback intent; unknown fields,
// trailing data and any text that is not the canonical rendering are refused.
func ParseRollbackIntent(canonical string) (RollbackIntent, error) {
	var i RollbackIntent
	dec := json.NewDecoder(bytes.NewReader([]byte(canonical)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&i); err != nil || dec.More() {
		return RollbackIntent{}, fmt.Errorf("%w: unreadable", ErrRollbackIntent)
	}
	if err := i.validate(); err != nil {
		return RollbackIntent{}, err
	}
	if again, err := i.Canonical(); err != nil || again != canonical {
		return RollbackIntent{}, fmt.Errorf("%w: not canonical", ErrRollbackIntent)
	}
	return i, nil
}

// NewRollbackIntent builds the intent for a record already judged usable.
func NewRollbackIntent(rec *Record) RollbackIntent {
	return RollbackIntent{
		Kind: RollbackIntentKind, Tenant: rec.Tenant, Service: rec.Service,
		TargetDeploymentID: rec.ID, TargetCommit: rec.CommitSHA, ExpectedDigest: rec.ImageDigest,
	}
}

// RollbackValuesAfter is the text a rollback plan stores where a deploy plan
// stores rendered values: the file is restored from git by the workflow, so
// it is described, not rendered. The plan digest binds this text and the
// intent, and the approval page shows it.
func RollbackValuesAfter(in RollbackIntent) string {
	return "# values.yaml is restored as it was at mctl-gitops commit " + in.TargetCommit +
		" (deployment " + in.TargetDeploymentID + ", image digest " + in.ExpectedDigest + ")\n"
}
