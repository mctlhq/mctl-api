import { createHash } from 'node:crypto';

export const NETWORK = 'eip155:84532';
export const ASSET = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
export const FACILITATOR = 'https://x402.org/facilitator';
export const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
export const HASH = /^0x[0-9a-fA-F]{64}$/;

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
export function requirements(recipient) {
  if (!ADDRESS.test(recipient) || /^0x0{40}$/i.test(recipient)) throw Error('Invalid testnet recipient');
  return { scheme: 'exact', network: NETWORK, asset: ASSET, amount: '10000', payTo: recipient,
    maxTimeoutSeconds: 60, extra: { name: 'USDC', version: '2' } };
}

export function validatePayment(p, data, payer, now, checkExpiry = true) {
  const a = p?.payload?.authorization;
  if (p?.x402Version !== 2 || canonical(p.accepted) !== canonical(data.requirements) ||
      p.resource?.url !== data.resource.url || !a || !ADDRESS.test(a.from) ||
      a.from.toLowerCase() !== payer.toLowerCase() ||
      a.to?.toLowerCase() !== data.requirements.payTo.toLowerCase() ||
      a.value !== data.requirements.amount || a.nonce?.toLowerCase() !== data.nonce ||
      !/^0x[0-9a-fA-F]{130}$/.test(p.payload.signature) ||
      !/^\d{1,12}$/.test(a.validAfter) || !/^\d{1,12}$/.test(a.validBefore)) {
    throw Error('Payment binding invalid');
  }
  // The EIP-3009 nonce binds a signed authorization to this exact pilot
  // principal/request/endpoint/price. Resource metadata alone is not signed.
  const before = Number(a.validBefore), after = Number(a.validAfter);
  if (before <= after || before > data.expires ||
      (checkExpiry && (now >= data.expires || now <= after || now >= before))) {
    throw Error('Payment validity invalid');
  }
}

async function limitedJSON(response, cap = 65536) {
  if (!response.ok) throw Error('Facilitator unavailable');
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > cap) throw Error('Facilitator response too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// Narrow protocol adapter, not a simulated authorize/capture/void adapter.
// Cryptographic verification and chain settlement are delegated to the pinned
// facilitator. This process never holds a wallet private key.
export class Facilitator {
  constructor(fetchFn = fetch) { this.fetch = fetchFn; }
  async request(path, body) {
    const response = await this.fetch(`${FACILITATOR}/${path}`, {
      method: body ? 'POST' : 'GET', redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body && JSON.stringify(body),
    });
    return limitedJSON(response);
  }
  async supported() {
    const result = await this.request('supported');
    if (!result.kinds?.some(k => k.x402Version === 2 && k.scheme === 'exact' && k.network === NETWORK)) {
      throw Error('Facilitator does not advertise testnet exact v2');
    }
  }
  verify(paymentPayload, paymentRequirements) {
    return this.request('verify', { x402Version: 2, paymentPayload, paymentRequirements });
  }
  settle(paymentPayload, paymentRequirements) {
    return this.request('settle', { x402Version: 2, paymentPayload, paymentRequirements });
  }
}
