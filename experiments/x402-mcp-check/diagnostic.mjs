import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const PROTOCOL = '2025-06-18';
const CAP = 1048576;

export function publicIP(ip) {
  if (isIP(ip) === 4) {
    const [a,b,c] = ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0) || (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113));
  }
  // Deliberately conservative pilot: only native global-unicast IPv6, with
  // transition/special ranges excluded. IPv4-mapped forms are all rejected.
  if (isIP(ip) === 6) {
    const lower = ip.toLowerCase();
    return /^[23]/.test(lower) && !/^2001:/.test(lower) && !/^2002:/.test(lower) &&
      !/^3fff:/.test(lower);
  }
  return false;
}
export function endpointURL(raw) {
  const u = new URL(raw);
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.search ||
      (u.port && u.port !== '443') || isIP(u.hostname.replace(/^\[|\]$/g, ''))) {
    throw Error('Endpoint must be an HTTPS hostname on port 443 without credentials/query/fragment');
  }
  return u;
}

// Validate every DNS answer and connect to the validated address through
// request-local lookup; TLS SNI/certificate verification remains the hostname.
export async function targetRequest(raw, body, { signal, session, resolve = lookup } = {}) {
  const u = endpointURL(raw);
  signal?.throwIfAborted();
  let abortDNS;
  const aborted = new Promise((_, reject) => {
    abortDNS = () => reject(Error('Target deadline exceeded'));
    signal?.addEventListener('abort', abortDNS, { once: true });
  });
  let answers;
  try { answers = await Promise.race([resolve(u.hostname, { all: true, verbatim: true }), aborted]); }
  finally { signal?.removeEventListener('abort', abortDNS); }
  if (!answers.length || answers.some(a => !publicIP(a.address))) throw Error('Target address denied');
  return new Promise((resolveResponse, reject) => {
    const req = https.request(u, { method: 'POST', agent: false, signal,
      lookup: (_host, options, cb) => {
        const answer = answers[0];
        if (options.all) cb(null, [answer]); else cb(null, answer.address, answer.family);
      },
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': PROTOCOL, ...(session ? { 'Mcp-Session-Id': session } : {}) },
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > CAP) res.destroy(Error('Target response too large'));
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode === 202 && !('id' in body)) return resolveResponse({});
        if (res.statusCode !== 200) return reject(Error(`Target HTTP ${res.statusCode}`));
        if (!String(res.headers['content-type']).startsWith('application/json')) {
          return reject(Error('Target SSE response unsupported by pilot'));
        }
        try {
          const json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (json.jsonrpc !== '2.0' || json.id !== body.id || json.error || !json.result ||
              typeof json.result !== 'object' || Array.isArray(json.result)) throw Error('Invalid MCP response');
          const sid = res.headers['mcp-session-id'];
          if (sid && (Array.isArray(sid) || sid.length > 256 || /[^\x21-\x7e]/.test(sid))) {
            throw Error('Invalid target session');
          }
          resolveResponse({ result: json.result, session: sid });
        } catch { reject(Error('Invalid MCP response')); }
      });
    });
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

const safeName = x => typeof x === 'string' && /^[A-Za-z0-9_.:/-]{1,128}$/.test(x);
export async function diagnose(url, { request = targetRequest, timeout = 20000 } = {}) {
  const started = Date.now();
  const signal = AbortSignal.timeout(timeout);
  const report = { profile: 'mctl-mcp-check/1', started_at: new Date(started).toISOString(),
    checks: [], tools: [], verdict: 'fail' };
  try {
    const initialized = await request(url, { jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: PROTOCOL, capabilities: {},
        clientInfo: { name: 'mctl-mcp-check', version: '0.1.0' } } }, { signal });
    const r = initialized.result;
    if (r.protocolVersion !== PROTOCOL || !r.capabilities || !r.serverInfo ||
        typeof r.serverInfo.name !== 'string' || typeof r.serverInfo.version !== 'string') {
      throw Error('Unsupported initialize response');
    }
    report.checks.push({ step: 'initialize', outcome: 'pass' });
    report.protocol_version = r.protocolVersion;
    const opts = { signal, session: initialized.session };
    await request(url, { jsonrpc: '2.0', method: 'notifications/initialized' }, opts);
    if (!r.capabilities.tools) {
      report.checks.push({ step: 'tools/list', outcome: 'not_advertised' });
      report.verdict = 'partial';
    } else {
      let cursor; const seen = new Set();
      for (let page = 0; page < 3; page++) {
        const { result } = await request(url, { jsonrpc: '2.0', id: page + 2, method: 'tools/list',
          params: cursor ? { cursor } : {} }, opts);
        if (!Array.isArray(result.tools)) throw Error('Invalid tools/list response');
        let warnings = 0;
        const remaining = 100 - report.tools.length;
        for (const tool of result.tools) {
          if (report.tools.length >= 100) break;
          const valid = tool && safeName(tool.name) && tool.inputSchema?.type === 'object' &&
            !seen.has(tool.name);
          if (!valid) warnings++;
          if (tool && safeName(tool.name)) seen.add(tool.name);
          report.tools.push({ name: tool && safeName(tool.name) ? tool.name : '[invalid-name]',
            schema_shape_valid: Boolean(valid) });
        }
        report.checks.push({ step: 'tools/list', page: page + 1, outcome: warnings ? 'warning' : 'pass' });
        if (warnings) report.verdict = 'partial';
        if (result.nextCursor && (typeof result.nextCursor !== 'string' || result.nextCursor.length > 1024)) {
          throw Error('Invalid pagination cursor');
        }
        if (result.tools.length > remaining ||
            (result.nextCursor && (page === 2 || report.tools.length === 100))) {
          report.checks.push({ step: 'bounds', outcome: 'truncated' }); report.verdict = 'partial'; break;
        }
        cursor = result.nextCursor;
        if (!cursor) { if (report.verdict !== 'partial') report.verdict = 'pass'; break; }
      }
    }
  } catch (e) {
    // Never expose target-provided errors, stack traces, names/descriptions,
    // session IDs, auth challenges or arbitrary response content.
    report.checks.push({ step: 'target', outcome: signal.aborted ? 'timeout' : 'failed',
      reason: 'Target did not satisfy the bounded MCP diagnostic profile' });
    report.verdict = 'fail';
  }
  report.duration_ms = Date.now() - started;
  report.tool_count = report.tools.length;
  return report;
}
