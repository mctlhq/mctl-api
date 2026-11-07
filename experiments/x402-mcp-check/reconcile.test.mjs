import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from './store.mjs';
import { reconcile } from './reconcile.mjs';
import { ASSET, NETWORK } from './payment.mjs';

const payer='0x1111111111111111111111111111111111111111';
const recipient='0x2222222222222222222222222222222222222222';
const nonce=`0x${'a'.repeat(64)}`,tx=`0x${'b'.repeat(64)}`,blockHash=`0x${'c'.repeat(64)}`;
const used=`0x${'d'.repeat(64)}`,transfer=`0x${'e'.repeat(64)}`;
const pad=a=>`0x${a.slice(2).padStart(64,'0')}`;
function fixture(){
  const store=new Store(':memory:');
  store.create('id','binding',{invocationID:'pilot_fixture',payer,nonce,expires:Math.floor(Date.now()/1000)+60,
    requirements:{payTo:recipient,amount:'10000'}},1000);
  store.move('id','challenged','settlement_unknown',1000,{report:{verdict:'pass'}});
  const logs=[{address:ASSET,transactionHash:tx,topics:[used,pad(payer),nonce],data:'0x'},
    {address:ASSET,transactionHash:tx,topics:[transfer,pad(payer),pad(recipient)],data:`0x${(10000).toString(16).padStart(64,'0')}`}];
  const receipt={status:'0x1',transactionHash:tx,blockNumber:'0x10',blockHash,logs};
  const rpc={call:async(method,params)=>{
    if(method==='eth_chainId')return '0x14a34';
    if(method==='web3_sha3')return Buffer.from(params[0].slice(2),'hex').toString().startsWith('AuthorizationUsed')?used:transfer;
    if(method==='eth_getBlockByNumber')return {number:params[0]==='finalized'?'0x20':'0x10',hash:blockHash};
    if(method==='eth_getLogs')return [logs[0]];
    if(method==='eth_getTransactionReceipt')return receipt;
    throw Error('unexpected RPC');
  }};
  return {store,rpc,receipt,logs};
}
test('lost tx hash is discovered by nonce and unlocks exact finalized report',async()=>{
  const f=fixture();const r=await reconcile(f.store,'pilot_fixture',f.rpc);
  assert.deepEqual(r,{success:true,network:NETWORK,payer,transaction:tx});
  assert.equal(f.store.get('id').phase,'settled');assert.deepEqual(f.store.get('id').report,{verdict:'pass'});
  assert.deepEqual(await reconcile(f.store,'pilot_fixture',f.rpc),r);f.store.close();
});
for(const [name,mutate]of[
  ['wrong token',f=>f.logs[0].address=recipient],['wrong nonce',f=>f.logs[0].topics[2]=used],
  ['wrong payer',f=>f.logs[1].topics[1]=pad(recipient)],['wrong payee',f=>f.logs[1].topics[2]=pad(payer)],
  ['wrong amount',f=>f.logs[1].data=`0x${'0'.repeat(64)}`],['reverted',f=>f.receipt.status='0x0'],
  ['unfinalized',f=>f.receipt.blockNumber='0x21'],['removed log',f=>f.logs[0].removed=true],
  ['wrong tx',f=>f.receipt.transactionHash=nonce],['wrong block',f=>f.receipt.blockHash=nonce],
])test(`reconciliation rejects ${name}`,async()=>{
  const f=fixture();mutate(f);await assert.rejects(reconcile(f.store,'pilot_fixture',f.rpc,tx));
  assert.equal(f.store.get('id').phase,'settlement_unknown');f.store.close();
});
test('wrong chain and missing chain evidence fail closed',async()=>{
  const f=fixture();await assert.rejects(reconcile(f.store,'pilot_fixture',{call:async()=> '0x2105'},tx),/Wrong chain/);
  await assert.rejects(reconcile(f.store,'pilot_fixture',{call:async()=>{throw Error('unavailable');}},tx));
  assert.equal(f.store.get('id').phase,'settlement_unknown');f.store.close();
});
