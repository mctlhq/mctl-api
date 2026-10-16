import { mkdirSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ASSET, HASH, NETWORK } from './payment.mjs';
import { Store } from './store.mjs';

const hexNumber = n => `0x${n.toString(16)}`;
const addressTopic = a => `0x${a.slice(2).toLowerCase().padStart(64,'0')}`;
const same = (a,b) => typeof a==='string' && typeof b==='string' && a.toLowerCase()===b.toLowerCase();

export class ChainRPC {
  constructor(url, fetchFn=fetch) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) throw Error('Configure trusted HTTPS Base Sepolia RPC');
    this.url=url;this.fetch=fetchFn;
  }
  async call(method,params) {
    const r=await this.fetch(this.url,{method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),
      headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
    if(!r.ok)throw Error('RPC unavailable');
    const chunks=[];let size=0;
    for await(const chunk of r.body){size+=chunk.length;if(size>1048576)throw Error('RPC response too large');chunks.push(chunk);}
    const json=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if(json.jsonrpc!=='2.0'||json.id!==1||json.error||!Object.hasOwn(json,'result'))throw Error('RPC failed');
    return json.result;
  }
}

// Never submits a transaction. Only unlocks a persisted report after finalized
// on-chain evidence of the exact token, payer, payee, amount and signed nonce.
// web3_sha3 performs Ethereum Keccak hashing of the ABI event signatures on
// the configured trusted RPC; unsupported RPCs fail closed.
export async function reconcile(store, invocationID, rpc, transaction, now=Math.floor(Date.now()/1000)) {
  store.purgeReports(now);
  const record=store.db.prepare("SELECT id FROM calls WHERE json_extract(data,'$.invocationID')=?").get(invocationID);
  const row=record&&store.get(record.id);
  if(!row||!row.report||!['settlement_unknown','settled'].includes(row.phase))throw Error('No recoverable diagnostic report');
  if(row.phase==='settled')return row.receipt;
  if(await rpc.call('eth_chainId',[])!==hexNumber(84532))throw Error('Wrong chain');
  const finalized=await rpc.call('eth_getBlockByNumber',['finalized',false]);
  if(!/^0x[0-9a-f]+$/i.test(finalized?.number))throw Error('Finalized block unavailable');
  const finalNumber=BigInt(finalized.number);
  const topic=async name=>{
    const value=await rpc.call('web3_sha3',[`0x${Buffer.from(name).toString('hex')}`]);
    if(!HASH.test(value))throw Error('Event topic unavailable');return value;
  };
  const used=await topic('AuthorizationUsed(address,bytes32)');
  const transfer=await topic('Transfer(address,address,uint256)');
  const payerTopic=addressTopic(row.data.payer || row.receipt?.payer);
  // Older records also carry payer in their requirements binding but not data.
  // New records persist it explicitly; absence prevents ambiguous recovery.
  const nonce=row.data.nonce;
  let tx=transaction||row.receipt?.transaction;
  if(tx&&!HASH.test(tx))throw Error('Invalid transaction hash');
  if(!tx){
    const logs=await rpc.call('eth_getLogs',[{address:ASSET,
      fromBlock:hexNumber(finalNumber>4096n?finalNumber-4096n:0n),toBlock:finalized.number,
      topics:[used,payerTopic,nonce]}]);
    if(!Array.isArray(logs))throw Error('Invalid log lookup');
    const candidates=[...new Set(logs.filter(l=>!l.removed&&same(l.address,ASSET)&&
      same(l.topics?.[0],used)&&same(l.topics?.[1],payerTopic)&&same(l.topics?.[2],nonce))
      .map(l=>l.transactionHash).filter(h=>HASH.test(h)))];
    if(candidates.length!==1)throw Error('No unique finalized authorization in bounded lookup; supply verified candidate hash');
    [tx]=candidates;
  }
  const receipt=await rpc.call('eth_getTransactionReceipt',[tx]);
  if(receipt?.status!=='0x1'||!same(receipt.transactionHash,tx)||
      !/^0x[0-9a-f]+$/i.test(receipt.blockNumber)||BigInt(receipt.blockNumber)>finalNumber||!Array.isArray(receipt.logs)){
    throw Error('Transaction is not a successful finalized receipt');
  }
  const block=await rpc.call('eth_getBlockByNumber',[receipt.blockNumber,false]);
  if(!same(block?.hash,receipt.blockHash))throw Error('Receipt block is not canonical');
  const logs=receipt.logs.filter(l=>!l.removed&&same(l.address,ASSET)&&same(l.transactionHash,tx));
  const hasNonce=logs.some(l=>l.topics?.length===3&&same(l.topics[0],used)&&
    same(l.topics[1],payerTopic)&&same(l.topics[2],nonce));
  const hasTransfer=logs.some(l=>l.topics?.length===3&&same(l.topics[0],transfer)&&
    same(l.topics[1],payerTopic)&&same(l.topics[2],addressTopic(row.data.requirements.payTo))&&
    /^0x[0-9a-f]{64}$/i.test(l.data)&&BigInt(l.data)===BigInt(row.data.requirements.amount));
  if(!hasNonce||!hasTransfer)throw Error('Receipt does not prove this exact authorization and transfer');
  const result={success:true,network:NETWORK,payer:row.data.payer,transaction:tx};
  if(!store.move(row.id,'settlement_unknown','settled',now,{receipt:result}))throw Error('Recovery state changed');
  return result;
}

async function main(argv,env=process.env){
  if(env.MCTL_X402_PILOT_ENABLED!=='testnet')throw Error('Testnet only');
  const [invocationID,tx]=argv;
  if(!invocationID)throw Error('Specify invocation id');
  const path=resolve(env.MCTL_X402_PILOT_DB||'./state/pilot.sqlite'),lock=`${path}.lock`;
  mkdirSync(lock,{mode:0o700}); // Stop server first, or refuse shared ownership.
  let store;
  try {store=new Store(path);return await reconcile(store,invocationID,new ChainRPC(env.MCTL_X402_PILOT_RPC),tx);}
  finally {store?.close();rmSync(lock,{recursive:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  process.umask(0o077);
  main(process.argv.slice(2)).then(r=>console.log(JSON.stringify(r,null,2))).catch(()=>{
    console.error('Reconciliation refused; check process ownership and finalized chain evidence');process.exitCode=1;
  });
}
