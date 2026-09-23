import json, sys
sys.path.insert(0, '.')
from orchestrator.human_input import (seal_request, ResponseSpec, RequestedFrom)
from orchestrator.context_snapshot import ExecutionCorrelation
ex = ExecutionCorrelation(agent="issue-investigator", environment="production",
    temporal_workflow_id="dev-loop-mctlhq-mctl-api-261", target_repository_sha="c963963",
    definition_version="1", definition_content_hash="sha256:"+"a"*64,
    profile_version="1.3.0", profile_content_hash="sha256:"+"b"*64, release_revision=10,
    temporal_run_id="run-1", argo_workflow_name=None)
cases = {
 "ascii_single_choice": dict(question="Which library should the fix use?", reason="Two libraries are viable.",
    response=ResponseSpec(type="single_choice", options=("library A","library B"), schema_ref=None),
    requested_from=RequestedFrom(audience="work_item_owner", actor_refs=("github:alice",)),
    context_refs=("github:mctlhq/mctl-api#261",)),
 "unicode_free_text": dict(question="Какой вариант — «A» или «B»? 🚀 <tag> & \"q\"\n\ttab  ", reason="Straße ß 中文",
    response=ResponseSpec(type="free_text", options=(), schema_ref=None),
    requested_from=RequestedFrom(audience="repo_operators", actor_refs=("github:alice","telegram:12345")),
    context_refs=()),
 "multi_structured_round2": dict(question="Pick any.", reason="r", round=2, request_version=3,
    response=ResponseSpec(type="multi_choice", options=("x","y","z"), schema_ref="schema://x"),
    requested_from=RequestedFrom(audience="tenant_operators", actor_refs=("github:bob",)),
    context_refs=("evidence:e1","gitops-file:platform-gitops/x.yaml")),
}
for name, kw in cases.items():
    r = seal_request(work_item_id="wi-261", execution=ex, created_at="2026-09-23T02:00:00Z",
                     expires_at="2026-09-24T02:00:00Z", **kw)
    doc = r.to_dict()
    open(f"{sys.argv[1]}/{name}.json","w").write(json.dumps(doc, indent=2, ensure_ascii=False))
    print(name, doc["request_id"], doc["request_hash"])
