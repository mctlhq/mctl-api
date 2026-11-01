package reviewreceipts

import "testing"

func TestSubjectKeysAreInjective(t *testing.T) {
	a := ReviewSubject{Kind: SubjectProposal, Service: "mctl-api", Slug: "s", ContentDigest: "sha256:" + string(make([]byte, 0)), GitopsCommit: "x"}
	b := a
	b.GitopsCommit = "y" // provenance only
	if a.Binding().Key() != b.Binding().Key() {
		t.Fatal("gitops_commit must not change the binding key")
	}
	if a.Identity().Key() != b.Identity().Key() {
		t.Fatal("identity key differs")
	}
	c := a
	c.ContentDigest = "other"
	if a.Binding().Key() == c.Binding().Key() {
		t.Fatal("content_digest must change the binding key")
	}
	d := a
	d.Slug = "t"
	if a.Identity().Key() == d.Identity().Key() {
		t.Fatal("slug must change the identity key")
	}
}
