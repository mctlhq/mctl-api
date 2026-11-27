import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { mkdirSync, rmSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Store } from './store.mjs';
import { Facilitator } from './payment.mjs';
import { Pilot } from './pilot.mjs';

function authorized(header, token) {
  const a = Buffer.from(header || ''), b = Buffer.from(`Bearer ${token}`);
  return a.length === b.length && timingSafeEqual(a,b);
}
export function serverFor(pilot, token) {
  if (typeof token !== 'string' || token.length < 32) throw Error('Pilot token must have at least 32 characters');
  return createServer(async (req,res) => {
    const send = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(data === undefined ? undefined : JSON.stringify(data));
    };
    if (req.url !== '/mcp') return send(404, { error: 'Not found' });
    if (!authorized(req.headers.authorization, token)) return send(401, { error: 'Unauthorized' });
    if (req.headers.origin) return send(403, { error: 'Browser-origin requests unsupported by pilot' });
    if (req.method !== 'POST') return send(405, { error: 'POST required' });
    if (!String(req.headers['content-type']).startsWith('application/json')) return send(415, { error: 'JSON required' });
    let rpc;
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 65536) return send(413, { error: 'Request too large' });
        chunks.push(chunk);
      }
      rpc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!rpc || rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string' || Array.isArray(rpc) ||
          (Object.hasOwn(rpc,'id') && !(typeof rpc.id === 'string' || Number.isSafeInteger(rpc.id)))) {
        return send(400, { jsonrpc:'2.0', id:null, error:{code:-32600,message:'Invalid Request'} });
      }
      if (!Object.hasOwn(rpc,'id')) {
        if (rpc.method === 'notifications/initialized') return send(202);
        return send(400, { error: 'Only initialized notifications are supported' });
      }
      let result;
      if (rpc.method === 'initialize') {
        if (rpc.params?.protocolVersion !== '2025-06-18') {
          return send(200, { jsonrpc:'2.0',id:rpc.id,error:{code:-32602,message:'Pilot requires MCP 2025-06-18'} });
        }
        result = { protocolVersion:'2025-06-18', capabilities:{tools:{}},
          serverInfo:{name:'mctl-x402-mcp-check-pilot',version:'0.1.0'} };
      } else if (rpc.method === 'tools/list') result = { tools: pilot.tools() };
      else if (rpc.method === 'ping') result = {};
      else if (rpc.method === 'tools/call') result = await pilot.call(rpc.params);
      else return send(200, {jsonrpc:'2.0',id:rpc.id,error:{code:-32601,message:'Method not found'}});
      send(200,{jsonrpc:'2.0',id:rpc.id,result});
    } catch {
      send(rpc ? 500 : 400, { jsonrpc:'2.0',id:rpc?.id??null,
        error:{code:rpc?-32603:-32700,message:rpc?'Internal error; retain request identity':'Parse error'} });
    }
  });
}

export async function start(env = process.env) {
  if (env.MCTL_X402_PILOT_ENABLED !== 'testnet') throw Error('Set MCTL_X402_PILOT_ENABLED=testnet explicitly');
  const token = env.MCTL_X402_PILOT_TOKEN;
  if (!token || token.length < 32) throw Error('Configure a separate pilot bearer token');
  const path = resolve(env.MCTL_X402_PILOT_DB || './state/pilot.sqlite');
  mkdirSync(dirname(path), { recursive:true,mode:0o700 });
  const lock = `${path}.lock`;
  mkdirSync(lock, { mode:0o700 }); // Refuse a second process; never steal stale lock.
  let store;
  try {
    store = new Store(path);
    const facilitator = new Facilitator();
    const pilot = new Pilot({store,facilitator,recipient:env.MCTL_X402_PILOT_RECIPIENT,
      payer:env.MCTL_X402_PILOT_PAYER, endpoints:JSON.parse(env.MCTL_X402_PILOT_ENDPOINTS || '{}')});
    await facilitator.supported();
    store.recover(Math.floor(Date.now()/1000));
    store.purgeReports(Math.floor(Date.now()/1000));
    const server = serverFor(pilot,token);
    server.requestTimeout = 5000; server.headersTimeout = 5000;
    server.on('close',()=>{ store.close();rmSync(lock,{recursive:true}); });
    const port = Number(env.MCTL_X402_PILOT_PORT || 8787);
    if (!Number.isInteger(port) || port<1 || port>65535) throw Error('Invalid pilot port');
    await new Promise((ok,fail)=>{server.once('error',fail);server.listen(port,'127.0.0.1',ok);});
    return server;
  } catch(e) { store?.close();rmSync(lock,{recursive:true});throw e; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.umask(0o077);
  start().then(server=>{
    console.log('MCP Check testnet pilot listening on loopback; no production routes enabled');
    for (const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>server.close());
  }).catch(()=>{console.error('Pilot startup failed: check configuration, supported networks and database lock');process.exitCode=1;});
}
