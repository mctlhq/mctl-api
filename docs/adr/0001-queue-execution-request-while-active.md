# ADR 0001: Queue an execution request while an execution is active

Status: accepted (behind a switch, off by default)

## Context

Create refused a request with 409 `execution_active` while the work item had
a Pending or Running execution, and stored nothing. mctl-agents#992 keeps the
DevLoop's canonical execution open through the whole implement run, so the
refusal window grows to minutes. A request made in it must not be lost.

## Decision

With `MCTL_EXECUTION_REQUEST_QUEUE_WHILE_ACTIVE=on`:

- create stores a `pending` request when the open execution is the only
  blocker; every other check is unchanged;
- claim never returns a request of an item that has an open execution;
- fulfil is unchanged, so a stale `expected_state_version` fails with
  `state_version_conflict` and an open execution with `execution_active`;
- a sweeper closes `temporal` executions whose run is already closed or
  gone (to `Error`, with an `execution_orphan_closed` event) so a queued
  request is not blocked forever. It fails closed: a run it cannot read is
  never treated as closed.

Off (the default) keeps today's behaviour byte for byte.

## Rejected

- A second execution on the same item: the one-open-execution index refuses
  it just the same.
- A separate table of deferred requests: it duplicates idempotency, one-open
  and fencing that the `pending` state already provides.
- Refusing and having surfaces retry: loses requests and spreads retry state.
- An unconditional claim guard: it would change behaviour with the switch off.
- Orphan closure only in mctl-agents: a terminated loop runs no code.

## Rollout

Release with the switch off, turn it on in mctl-gitops, enable the
mctl-agents dispatcher, then let mctl-agents#992 out of draft. Rollback is
setting the switch to `off`; queued rows stay valid and fulfil defers them
until the execution ends. No schema change.
