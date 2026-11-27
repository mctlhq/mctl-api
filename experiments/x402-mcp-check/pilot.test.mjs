import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from './store.mjs';
import { Pilot } from './pilot.mjs';
import { Facilitator, NETWORK, ASSET } from './payment.mjs';
import { signingBundle } from './buyer.mjs';
import { serverFor } from './server.mjs';

const payer = '0x1111111111111111111111111111111111111111';
const recipient = '0x2222222222222222222222222222222222222222';
const transaction = `0x${'a'.repeat(64)}`;
const args = {endpoint_id:'fixture',request_id:'request_00000000001'};
const call = (arguments_=args,payment) => ({name:'mctl_mcp_check',arguments:arguments_,
  ...(payment?{_meta:{'x402/payment':payment}}:{})});
function fixture(overrides={}) {
  let now=1000, executions=0, settlements=0, verifications=0;
  const store=new Store(':memory:');
  const facilitator={verify:async()=>{verifications++;return {isValid:true,payer};},
    settle:async()=>{settlements++;return {success:true,payer,network:NETWORK,transaction};}};
  const pilot=new Pilot({store,facilitator,recipient,payer,endpoints:{fixture:'https://example.com/mcp'},
    clock:()=>now,diagnostic:async()=>{executions++;return {verdict:'pass'};},...overrides});
  return {pilot,store,facilitator,setNow:n=>{now=n;},counts:()=>({executions,settlements,verifications})};
}
async function proof(f,arguments_=args) {
  const c=(await f.pilot.call(call(arguments_))).structuredContent;
  const b=signingBundle(c,payer,1000);
  b.payment.payload.signature=`0x${'1'.repeat(130)}`;
  return b.payment;
}

test('challenge uses standard MCP dual encoding; no execution or charge',async()=>{
  const f=fixture();const r=await f.pilot.call(call());
  assert.equal(r.isError,true);assert.deepEqual(JSON.parse(r.content[0].text),r.structuredContent);
  assert.equal(r.structuredContent.accepts[0].network,NETWORK);
  assert.equal(r.structuredContent.accepts[0].asset,ASSET);
  assert.deepEqual(f.counts(),{executions:0,settlements:0,verifications:0});f.store.close();
});
test('valid payment, stable result/receipt and no repeated verification or settlement',async()=>{
  const f=fixture();const p=await proof(f);const r=await f.pilot.call(call(args,p));
  assert.equal(r.isError,false);assert.equal(r._meta['x402/payment-response'].transaction,transaction);
  f.setNow(1200); // Original authorization expired; authenticated exact-proof recovery still works.
  assert.deepEqual(await f.pilot.call(call(args,p)),r);
  assert.deepEqual(f.counts(),{executions:1,settlements:1,verifications:1});f.store.close();
});
test('concurrent duplicate has one execution and one settlement',async()=>{
  const f=fixture();const p=await proof(f);
  const rs=await Promise.all([f.pilot.call(call(args,p)),f.pilot.call(call(args,p))]);
  assert.equal(rs.filter(r=>!r.isError).length,1);
  assert.deepEqual(f.counts(),{executions:1,settlements:1,verifications:1});f.store.close();
});
for (const [name,mutate] of [
  ['amount',p=>p.accepted.amount='1'],['network',p=>p.accepted.network='eip155:8453'],
  ['asset',p=>p.accepted.asset=recipient],['recipient',p=>p.payload.authorization.to=payer],
  ['payer',p=>p.payload.authorization.from=recipient],['nonce',p=>p.payload.authorization.nonce=`0x${'f'.repeat(64)}`],
  ['expiry',p=>p.payload.authorization.validBefore='999'],['validity span',p=>p.payload.authorization.validAfter='1061'],
  ['unsigned resource',p=>p.resource.url='mcp://tool/different'],['unsupported permit2',p=>{p.payload.authorization=null;}],
]) test(`reject ${name} before facilitator and execution`,async()=>{
  const f=fixture();const p=await proof(f);mutate(p);
  assert.equal((await f.pilot.call(call(args,p))).isError,true);
  assert.deepEqual(f.counts(),{executions:0,settlements:0,verifications:0});f.store.close();
});
test('cross-request authorization replay rejected; same key changed args conflicts',async()=>{
  const f=fixture();const p=await proof(f);await f.pilot.call(call(args,p));
  assert.equal((await f.pilot.call(call({...args,request_id:'request_00000000002'},p))).isError,true);
  f.pilot.endpoints.second='https://example.org/mcp';
  assert.match((await f.pilot.call(call({...args,endpoint_id:'second'},p))).structuredContent.error,/conflicts/);
  assert.equal(f.counts().executions,1);f.store.close();
});
test('forged verification proof is rejected without consuming execution',async()=>{
  const f=fixture();const p=await proof(f);f.facilitator.verify=async()=>({isValid:false,payer});
  assert.equal((await f.pilot.call(call(args,p))).isError,true);assert.equal(f.counts().executions,0);f.store.close();
});
test('facilitator verification unavailable can retry without charge',async()=>{
  const f=fixture();const p=await proof(f);const verify=f.facilitator.verify;
  f.facilitator.verify=async()=>{throw Error('unavailable');};
  await f.pilot.call(call(args,p));assert.equal(f.counts().executions,0);
  f.facilitator.verify=verify;assert.equal((await f.pilot.call(call(args,p))).isError,false);f.store.close();
});
test('target fail report is delivered and charged, internal failure is not settled',async()=>{
  const f=fixture({diagnostic:async()=>({verdict:'fail',checks:[{outcome:'timeout'}]})});const p=await proof(f);
  const r=await f.pilot.call(call(args,p));assert.equal(r.isError,false);assert.equal(r.structuredContent.report.verdict,'fail');
  assert.equal(f.counts().settlements,1);f.store.close();
  const g=fixture({diagnostic:async()=>{throw Error('private internal stack');}});const q=await proof(g);
  const s=await g.pilot.call(call(args,q));assert.equal(s.structuredContent.payment_status,'internal_failed');
  assert.equal(g.counts().settlements,0);assert.doesNotMatch(JSON.stringify(s),/private internal/);g.store.close();
});
test('settlement timeout withholds report and never repeats diagnostic/settlement',async()=>{
  const f=fixture();const p=await proof(f);let attempts=0;
  f.facilitator.settle=async()=>{attempts++;throw Error('rpc secret');};
  const r=await f.pilot.call(call(args,p));assert.equal(r.structuredContent.payment_status,'settlement_unknown');
  assert.equal(r.structuredContent.report,undefined);
  assert.deepEqual(await f.pilot.call(call(args,p)),r);assert.equal(f.counts().executions,1);assert.equal(attempts,1);f.store.close();
});
test('malformed success or pending tx remains unknown with sanitized reference',async()=>{
  for(const receipt of [{success:true,payer,network:'eip155:8453',transaction},
    {success:false,errorReason:'settlement_pending',transaction,secret:'hidden'}]){
    const f=fixture();const p=await proof(f);f.facilitator.settle=async()=>receipt;
    const r=await f.pilot.call(call(args,p));assert.equal(r.structuredContent.payment_status,'settlement_unknown');
    assert.doesNotMatch(JSON.stringify(r),/hidden/);f.store.close();
  }
});
test('durable settled replay and crash recovery preserve no-rerun invariant',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'mcp-check-'));const path=join(dir,'pilot.sqlite');
  try {
    const store=new Store(path);const f=fixture({store});const p=await proof(f);
    const r=await f.pilot.call(call(args,p));store.close();f.store.close();
    const reopened=new Store(path);const g=fixture({store:reopened});reopened.recover(1001);
    assert.deepEqual(await g.pilot.call(call(args,p)),r);assert.equal(g.counts().executions,0);
    const h=await proof(g,{...args,request_id:'request_00000000003'});
    const row=reopened.db.prepare("SELECT id FROM calls WHERE phase='challenged'").get();
    reopened.move(row.id,'challenged','verifying',1000);
    reopened.move(row.id,'verifying','executing',1000,{proofHash:(await import('./payment.mjs')).digest(h)});
    reopened.move(row.id,'executing','settling',1000,{report:{verdict:'pass'}});
    reopened.recover(1002);
    assert.equal((await g.pilot.call(call({...args,request_id:'request_00000000003'},h))).structuredContent.payment_status,'settlement_unknown');
    assert.equal(g.counts().executions,0);reopened.close();g.store.close();
  } finally {rmSync(dir,{recursive:true,force:true});}
});
test('HTTP MCP auth and notification-only execution rejection',async()=>{
  const f=fixture(), token='t'.repeat(32), server=serverFor(f.pilot,token);
  await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
  const url=`http://127.0.0.1:${server.address().port}/mcp`;
  try {
    assert.equal((await fetch(url,{method:'POST'})).status,401);
    const request=body=>fetch(url,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
    assert.equal((await request({jsonrpc:'2.0',method:'tools/call',params:call()})).status,400);
    const r=await (await request({jsonrpc:'2.0',id:1,method:'tools/call',params:call()})).json();
    assert.equal(r.result.structuredContent.x402Version,2);assert.equal(f.counts().executions,0);
    const i=await (await request({jsonrpc:'2.0',id:2,method:'initialize',params:{protocolVersion:'2025-06-18'}})).json();
    assert.equal(i.result.protocolVersion,'2025-06-18');
  } finally {await new Promise(ok=>server.close(ok));f.store.close();}
});
test('Facilitator requests v2 envelopes and rejects unsupported network',async()=>{
  const requests=[];
  const facilitator=new Facilitator(async(url,init)=>{requests.push({url,init});return new Response(JSON.stringify({kinds:[{x402Version:2,scheme:'exact',network:NETWORK}]}));});
  await facilitator.supported();await facilitator.verify({a:1},{b:2});
  assert.deepEqual(JSON.parse(requests[1].init.body),{x402Version:2,paymentPayload:{a:1},paymentRequirements:{b:2}});
  assert.equal(requests[1].init.redirect,'error');
  await assert.rejects(new Facilitator(async()=>new Response('{"kinds":[]}')).supported());
});
