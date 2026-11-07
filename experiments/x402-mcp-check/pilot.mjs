import { randomUUID } from 'node:crypto';
import { ADDRESS, HASH, NETWORK, canonical, digest, requirements, validatePayment } from './payment.mjs';
import { endpointURL, diagnose } from './diagnostic.mjs';

export const TOOL = 'mctl_mcp_check';
const textResult = (data, isError = false, meta = {}) => ({ isError,
  content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data, _meta: meta });

export class Pilot {
  constructor({ store, facilitator, recipient, payer, principal = 'pilot-operator', endpoints,
    diagnostic = diagnose, clock = () => Math.floor(Date.now() / 1000) }) {
    this.store = store; this.facilitator = facilitator; this.req = requirements(recipient);
    if (!ADDRESS.test(payer) || /^0x0{40}$/i.test(payer)) throw Error('Invalid expected test payer');
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(principal)) throw Error('Invalid pilot principal');
    this.payer = payer; this.principal = principal; this.endpoints = endpoints;
    if (!endpoints || Object.keys(endpoints).length < 1 || Object.keys(endpoints).length > 10) {
      throw Error('Configure between one and ten allowlisted endpoints');
    }
    for (const [id, url] of Object.entries(endpoints)) {
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw Error('Invalid endpoint id');
      endpointURL(url);
    }
    this.diagnostic = diagnostic; this.clock = clock;
  }
  tools() {
    return [{ name: TOOL, description: 'Paid bounded MCP connection and tool discovery diagnostic. '
      + 'A completed report costs 0.01 test USDC, including a report of target failure. '
      + 'No target tools are executed. Base Sepolia only; payment-capable client required.',
      inputSchema: { type: 'object', additionalProperties: false,
        properties: { endpoint_id: { type: 'string', enum: Object.keys(this.endpoints) },
          request_id: { type: 'string', description: 'Stable logical request ID, 16-128 safe ASCII characters; retain on retries.' } },
        required: ['endpoint_id', 'request_id'] },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } }];
  }
  challenge(row, error = 'Payment required to access this resource') {
    return textResult({ x402Version: 2, error, resource: row.data.resource,
      accepts: [row.data.requirements], extensions: { 'mctl-request-binding': { info: {
        requestId: row.data.requestID, invocationId: row.data.invocationID,
        nonce: row.data.nonce, expires: row.data.expires,
        instruction: 'Sign EIP-3009 with this exact nonce and validBefore <= expires. '
          + 'This pilot requires a binding-aware payer; a generic auto-paying client may not support it.' } } } }, true);
  }
  outcome(row) {
    if (row.phase === 'settled') return textResult({ invocation_id: row.data.invocationID,
      endpoint_id: row.data.endpointID, report: row.report, payment_status: 'settled' }, false,
      { 'x402/payment-response': row.receipt });
    const result = this.challenge(row, 'Invocation requires recovery or is still processing; retain request_id. '
      + 'Do not create a replacement payment. Diagnostic result is withheld until confirmed settlement.');
    result.structuredContent.invocation_id = row.data.invocationID;
    result.structuredContent.payment_status = row.phase;
    result.content[0].text = JSON.stringify(result.structuredContent);
    return result;
  }
  async call(params) {
    const args = params?.arguments;
    if (params?.name !== TOOL || !args || typeof args !== 'object' || Array.isArray(args) ||
        Object.keys(args).some(k => !['endpoint_id','request_id'].includes(k)) ||
        !Object.hasOwn(this.endpoints, args.endpoint_id) ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(args.request_id)) {
      return textResult({ error: 'Invalid tool or input' }, true);
    }
    const now = this.clock();
    this.store.purgeReports(now);
    const id = digest({ principal: this.principal, requestID: args.request_id });
    const binding = digest({ profile: 'mctl-mcp-check/1', principal: this.principal,
      payer: this.payer.toLowerCase(), args, endpoint: this.endpoints[args.endpoint_id], requirements: this.req });
    const row = this.store.create(id, binding, { requestID: args.request_id,
      invocationID: `pilot_${randomUUID()}`, nonce: `0x${binding}`,
      endpointID: args.endpoint_id, endpoint: this.endpoints[args.endpoint_id],
      requirements: this.req, payer: this.payer, expires: now + 60,
      resource: { url: `mcp://tool/${TOOL}/${id}`, description: 'Bounded MCP diagnostic report', mimeType: 'application/json' } }, now);
    if (row.binding !== binding) return textResult({ error: 'Request identity conflicts with endpoint, payer or terms' }, true);
    const payment = params._meta?.['x402/payment'];
    if (!payment) {
      if (row.phase !== 'challenged') return textResult({ error: 'Original payment proof required for recovery' }, true);
      return this.challenge(row, now >= row.data.expires ? 'Challenge expired; use a new request_id before paying' : undefined);
    }
    try { validatePayment(payment, row.data, this.payer, now, row.phase === 'challenged'); }
    catch { return this.challenge(row, 'Payment binding invalid or expired'); }
    const proofHash = digest(payment);
    if (row.phase !== 'challenged') {
      // Authenticated pilot actor plus exact original proof, never wallet-as-admin.
      if (row.proof_hash !== proofHash) return textResult({ error: 'Original payment proof required' }, true);
      if (now > row.data.expires + 86400) return textResult({ error: 'Result recovery window expired; invocation will not repeat' }, true);
      return this.outcome(row);
    }
    if (!this.store.move(id, 'challenged', 'verifying', now)) {
      return textResult({ error: 'Request already processing; retry the same identity and proof' }, true);
    }
    let verified;
    try { verified = await this.facilitator.verify(payment, row.data.requirements); }
    catch {
      this.store.move(id, 'verifying', 'challenged', this.clock());
      return this.challenge(row, 'Payment verification unavailable; no diagnostic was executed');
    }
    if (verified?.isValid !== true || verified.payer?.toLowerCase() !== this.payer.toLowerCase()) {
      this.store.move(id, 'verifying', 'challenged', this.clock());
      return this.challenge(row, 'Payment verification failed');
    }
    if (this.clock() >= row.data.expires) {
      this.store.move(id, 'verifying', 'challenged', this.clock());
      return this.challenge(row, 'Payment expired before execution');
    }
    this.store.move(id, 'verifying', 'executing', this.clock(), { proofHash });
    let report;
    try { report = await this.diagnostic(row.data.endpoint); }
    catch {
      this.store.move(id, 'executing', 'internal_failed', this.clock());
      return this.outcome(this.store.get(id));
    }
    // Report persists before a settlement request can broadcast. A crash leaves
    // unknown settlement and withholds the report; it never re-executes a tool.
    this.store.move(id, 'executing', 'settling', this.clock(), { report });
    let receipt;
    try { receipt = await this.facilitator.settle(payment, row.data.requirements); }
    catch {
      this.store.move(id, 'settling', 'settlement_unknown', this.clock());
      return this.outcome(this.store.get(id));
    }
    const settled = receipt?.success === true && receipt.network === NETWORK &&
      receipt.payer?.toLowerCase() === this.payer.toLowerCase() && HASH.test(receipt.transaction);
    // A false/malformed response can follow a broadcast: remain conservative.
    // Persist only allowlisted fields, never arbitrary facilitator error text.
    const safeReceipt = { success: settled, network: NETWORK, payer: this.payer,
      ...(HASH.test(receipt?.transaction) ? { transaction: receipt.transaction } : {}) };
    this.store.move(id, 'settling', settled ? 'settled' : 'settlement_unknown', this.clock(), { receipt: safeReceipt });
    return this.outcome(this.store.get(id));
  }
}
