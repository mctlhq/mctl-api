# x402 MCP Check: isolated testnet pilot

This is an experimental Node 24.19+ command in the mctl-api repository, **not** a
new production API route, deployed service, or replacement for Agent Commerce.
It checks a configured public MCP endpoint's connection, initialize handshake
and tool catalogue. It never calls target tools. A completed diagnostic report
costs 0.01 **test** USDC, including a report explaining a target failure.

Related: [payment interop #549](https://github.com/mctlhq/mctl-api/issues/549).
The user selected MCP Check and authorized implementation of this testnet pilot
on 2026-10-13. No mainnet funds, production deployment or merchant onboarding.

## What runs

- Stateless JSON-response Streamable HTTP MCP endpoint on loopback `/mcp`.
- MCP protocol profile `2025-06-18`, initialize/ping/tools/list/tools/call.
- x402 v2 MCP challenge and `_meta` payment/receipt envelopes.
- Only `exact`, EIP-3009, Base Sepolia `eip155:84532`, the pinned test-USDC
  asset `0x036CbD53842c5426634e7929541eC2318f3dCF7e`, amount 10000 atomic units.
- Authenticated single pilot operator and one explicitly configured test payer.
  A wallet address does not grant MCTL tenant authority.
- Facilitator `/supported`, `/verify`, `/settle` via `https://x402.org/facilitator`.
  Startup refuses a facilitator that does not advertise v2 exact on this network.
- SQLite durable claims, outcome, payment reference and transition audit. One
  process only; synchronous FULL durability and committed claims before I/O.
- Binding-aware buyer CLI prepares EIP-712 typed data without accepting keys.

There are no npm dependencies. This slice uses a narrow facilitator wire adapter
and minimal MCP transport implementation, rather than integrating the full
official SDK into the Go control plane. The facilitator performs signature,
balance and chain checks. Local payload checks alone **do not** prove payment.
SDK adoption and generic-client interoperability remain #549 decisions.

## Run offline tests

```sh
cd experiments/x402-mcp-check
node --test
```

Tests use fake facilitator responses and injected target transports. Passing
them is **not** an on-chain payment or production network proof. They exercise
the actual HTTP pilot endpoint locally, durable SQLite reopen/recovery,
concurrency, replay, binding, failure/timeout and diagnostic bounds.

## Testnet run

Configure the following through your usual local secret/config mechanism;
never paste keys or bearer tokens into an issue or chat. No production secrets.

| Variable | Value |
|---|---|
| `MCTL_X402_PILOT_ENABLED` | literal `testnet` |
| `MCTL_X402_PILOT_TOKEN` | separate random bearer token, at least 32 characters |
| `MCTL_X402_PILOT_RECIPIENT` | test recipient public EVM address |
| `MCTL_X402_PILOT_PAYER` | external test wallet public EVM address |
| `MCTL_X402_PILOT_ENDPOINTS` | JSON mapping endpoint IDs to permitted public HTTPS URLs |
| `MCTL_X402_PILOT_DB` | optional dedicated durable SQLite path |
| `MCTL_X402_PILOT_PORT` | optional port, default 8787; binds 127.0.0.1 |

```sh
node server.mjs
node buyer.mjs prepare example check-bundle.json
```

`example` must be an endpoint ID in the configured allowlist. The prepare
command writes typed data, request identity and a payment template into a
0600 file. Sign `typedData` with an external Base Sepolia test wallet using
`eth_signTypedData_v4`; put the signature in `payment.payload.signature`.
The wallet needs test USDC; the provider never needs its private key. Send
within the 60-second challenge window:

```sh
node buyer.mjs send example check-bundle.json
```

Run the same send command to recover a lost response. Retain exactly the same
request ID and proof. An unpaid retry cannot retrieve an already-paid report.
The pilot requires the supplied nonce, which cryptographically binds the
authorization to principal/request/endpoint/payer/price. Generic x402 signers
that always generate a different random nonce need a binding hook; compatibility
with ChatGPT, Claude or arbitrary SDK clients is **not** claimed.

## Failure contract

| Event | Behavior |
|---|---|
| Invalid input, unknown endpoint or bad proof | no diagnostic or settlement |
| Facilitator verify fails/unavailable | no diagnostic; same request may retry |
| Target down, unsupported SSE, invalid handshake or target deadline | completed fail report; settlement attempted |
| Internal diagnostic exception | internal_failed; no settlement attempt |
| Settlement confirmed | report and standard settlement receipt delivered |
| Settlement timeout, false/malformed response | report persisted and withheld; settlement_unknown; operator can reconcile finalized chain evidence |
| Duplicate request | no new diagnostic/settlement; same stored outcome |
| Same request ID with changed endpoint, payer or terms | conflict |
| Restart with executing/verifying claim | outcome_unknown; never blindly rerun |
| Restart with settling claim | settlement_unknown; never blindly resubmit |

Unknown settlement is intentionally fail-closed. Stop the server cleanly and
configure `MCTL_X402_PILOT_RPC` with a trusted HTTPS Base Sepolia RPC. Run:

```sh
node reconcile.mjs pilot_INVOCATION_ID OPTIONAL_TRANSACTION_HASH
```

The command never submits a transaction. It checks chain ID, finalized block,
canonical receipt block, successful status and exact USDC AuthorizationUsed +
Transfer events for the persisted payer/nonce/payee/amount, then records settled
and unlocks the original report. It uses `web3_sha3` to obtain event topics;
RPC providers lacking this method fail closed. With no known hash it searches
the last 4096 finalized blocks for the exact authorization; older operations
require an operator-supplied candidate hash which is still fully checked.
Restart the server and resend the original buyer bundle to retrieve the report.
No arbitrary manual receipt is trusted. Background polling/refunds are absent.

This does not assert that all #549 requirements are satisfied. Streaming,
long-running jobs, MPP comparison and enterprise chargeback are also outside
this slice; no adapter pretends to support authorize/capture/void/refund.

## Bounds and isolation

- Public HTTPS hostname on port 443, no userinfo/query/fragment, no redirects.
- Validate every DNS answer, reject private/special/transition addresses, and
  pin the validated address for each request while retaining TLS verification.
- Up to 20 seconds overall target deadline, 1 MiB per response, 3 tools/list
  pages and 100 tools; unsupported SSE is reported as a profile limitation.
- Tool names only; no descriptions, raw schemas, server error messages,
  sessions, credentials or private response bodies in the report.
- Metadata is untrusted data, never executed instructions. Only initialize,
  initialized notification and tools/list are sent to a target.
- Intended for a single trusted operator. No anonymous public exposure, generic
  URL checker, multi-tenant auth, global budgets or rate-limit service claims.
- Reports are recoverable for 24 hours after quote expiry. Expired report data
  is cleared on startup, tool calls and reconciliation; a stopped service does
  not run a background purge. Requests/payment references remain tombstones and
  never execute again. Never reuse this DB as a production ledger.
- Stale `.lock` directory: prove the previous process is stopped before removing
  it. Restart then records uncertain operations. Never delete a running lock.

The existing EUR/simulated ledger and production MCP catalogue are untouched.
USDC atomic units are not EUR cents and no FX conversion is introduced.
Loopback access by a separate client process is the first transport test;
internet hosting, TLS and operator access controls need a separately reviewed
deployment configuration. Egress restrictions remain necessary at deployment.

## Remaining proof before calling the pilot complete

1. Confirm current facilitator network/asset behavior and actual test-token domain.
2. Sign and settle with dedicated external test wallets; capture sanitized refs.
3. Observe a real public target using this pinned JSON-response profile.
4. Prove the implemented operator reconciliation against a real finalized testnet
   transfer, including bounded nonce lookup after a lost facilitator hash.
5. Evaluate official SDK binding hooks and generic MCP-client behavior.
6. Decide integration with canonical MCTL identity, policy, budgets and ledger;
   this standalone experiment must not be presented as governed core execution.

## Protocol source pins

Audited x402 Foundation commit: `6c470a80c6145b27fcbb4f6359c47a6a8cfe5887`.

- [MCP transport](https://github.com/x402-foundation/x402/blob/6c470a80c6145b27fcbb4f6359c47a6a8cfe5887/specs/transports-v2/mcp.md), source blob `0dbd9e76eef52a30617012d50f868f9a5aff8dbb`.
- [exact EVM](https://github.com/x402-foundation/x402/blob/6c470a80c6145b27fcbb4f6359c47a6a8cfe5887/specs/schemes/exact/scheme_exact_evm.md), source blob `cda2ed42b0169e8db05969c193a8012f74fb0b20`.
- [EIP-3009 typed signing and authorization](https://eips.ethereum.org/EIPS/eip-3009).

Hosted facilitator implementation/version is not pin-able from these sources;
`/supported` is a startup gate, not a guarantee of the remote service's behavior.
