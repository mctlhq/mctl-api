# GitHub webhook → events producer

**Use this when** a pull request did not wake a session and you need to know
whether the event was ever produced, when you are reading a `202`/`401`/`503`
in GitHub's delivery log, or before changing anything about the org webhook or
the outbox.

How a pull request on GitHub becomes an event a running Claude session can be
woken by, what is deliberately *not* carried along the way, and how to tell
which half of the path is broken when nothing arrives.

Part of mctlhq/.github#87. The consumer side — the adapter, its routing policy,
delivery guarantees and the audit trail — lives in `mctlhq/mctl-claude-remote`
(`README.md` and `docs/events-operations.md`); this document stops at the
Valkey stream.

```
GitHub org webhook
  → POST /api/v1/webhooks/github   (internal/api/handlers_github_webhook.go)
  → outbox row, committed          (internal/events/outbox.go)
  → 202 {"status":"queued"}
  → relay: XADD mctl:events:github (internal/events/relay.go)
```

## Configuration

| Variable | Meaning |
|---|---|
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for `X-Hub-Signature-256`. Unset → every delivery answers 401. |
| `GITHUB_WEBHOOK_OWNERS` | Repository owners whose deliveries are queued (default `mctlhq`); anything else is answered 202 `ignored`. |
| `EVENTS_VALKEY_URL` | `redis://github-producer@valkey.platform-events.svc.cluster.local:6379/0` — the producer's own ACL user, which may `XADD` to `mctl:events:github` and nothing else. |

The webhook is configured **on the organisation**, not per repository, so a new
repository under an allowed owner is covered the day it is created. The live
one is hook `680944060` on `mctlhq`, pointing at
`https://api.mctl.ai/api/v1/webhooks/github`, content type `application/json`,
subscribed to `pull_request` and `pull_request_review` and nothing else
(`gh api orgs/mctlhq/hooks`).

## What the producer sends, and what it refuses to send

The envelope is a **reference, not content**. Only these fields are ever
decoded out of the delivery: action, PR number, head SHA, `updated_at`,
repository full name and owner, and `review.submitted_at`. Titles, bodies,
diffs and review text are not decoded into anything that outlives the request.

```json
{
  "specversion": "mctl.events/v1",
  "id": "github:0ccfdcce-b2d2-11f1-9e2e-e360579921db",
  "type": "github.pull_request.synchronize",
  "source": "mctl-api",
  "occurred_at": "2026-09-17T20:37:46Z",
  "correlation_id": "github:0ccfdcce-b2d2-11f1-9e2e-e360579921db",
  "subject": {
    "kind": "github.pull_request",
    "repository": "mctlhq/mctl-claude-remote",
    "number": "57",
    "head_sha": "616cf1e..."
  }
}
```

The id is GitHub's own delivery guid, prefixed. **Scope of what that
guarantees:** GitHub redelivers the *same delivery* under the same delivery
identifier, so using the guid as the event id makes redelivery idempotent
within this producer contract — a replay from the hook's delivery log produces
the same id, the outbox answers `duplicate`, and nothing new is published.

It says nothing about two *different* deliveries. A second push that produces
another `synchronize` for the same PR and even the same head SHA is a new
delivery with a new guid, and is a new event by design. Deduplication of
semantically similar events is the consumer's routing policy, not this id.

An event without a head SHA is rejected rather than queued: the head is what
identifies the revision the event is about, so an event without it would be
accepted and then not actionable. Claude reads the current state through `gh`
when it wakes, so a stale event is harmless — it hydrates what is true now, not
what was true at delivery.

## Why 202 comes after the database write

**A `202` here means durable acceptance, not downstream delivery.** It says the
envelope is committed to the outbox and will be published; it does not say the
relay has done an `XADD`, and certainly not that a session received or handled
anything. The `published` and `delivered` records in the audit trail are what
say that.

GitHub does not retry a failed delivery by itself. A `202` for an event that
was subsequently lost would be invisible; a `5xx` is visible in the hook's
delivery log and can be redelivered by hand. So the handler answers only once
the outbox row is committed, and answers `503` when the outbox or Valkey is not
configured or not reachable.

The response body says which of the two happened:

```json
{"status": "queued",    "event_id": "github:..."}   // new row
{"status": "duplicate", "event_id": "github:..."}   // this delivery was already accepted
```

Other answers: `401` (no secret configured, or a bad signature), `413` (body
over 1 MiB), `400` (unparsable, or missing repository/pull_request), `202`
`ignored` for an event type, action or owner that is not published, and `200`
`pong` for GitHub's ping.

## The relay

A background loop drains the outbox into Valkey. Worth knowing:

- **One publisher at a time**, held by a lease (TTL 1 min, renewed while rows
  are published rather than once per batch), so several `mctl-api` replicas
  cannot double-publish.
- **Batches of 100**, a safety sweep every 30 s even when nothing signals, and
  exponential backoff to a 1 min ceiling when Valkey is unhappy. A newly
  arrived row does not cut a failure backoff short.
- **`MAXLEN ~ 10000`** on the stream, so a session that has been away for a
  long time loses the oldest references rather than the cluster losing memory.
- **Published rows are purged after 7 days**, hourly.

## When nothing arrives

Work the path in order; each step distinguishes one half from the other.

1. **GitHub's delivery log** (org settings → webhook → Recent Deliveries) —
   the response code and body are recorded there. `401` means the secret does
   not match, `503` means this service could not reach its own storage, and a
   `202` with `"ignored"` names its own reason.
2. **The service log.** Every accepted delivery logs
   `github webhook accepted` with `event_id`, `type`, `repository`, `number`
   and `status`, so a delivery that GitHub says was accepted can be found by
   its guid.
3. **The stream.** `XLEN mctl:events:github` and the audit trail's `published`
   record for that `event_id` tell whether the relay got it out. A row that is
   in the outbox but not in the stream means the relay is failing or leaseless,
   not that the webhook is broken.
4. **Only then the consumer.** A `published` record with no `delivered` is the
   adapter's side; that path is documented in `mctl-claude-remote`,
   `docs/events-operations.md`.

Redelivering from GitHub's UI is safe at any point: it carries the original
delivery guid, so the outbox recognises it and answers `duplicate` rather than
producing a second event.
