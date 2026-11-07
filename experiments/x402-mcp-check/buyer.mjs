import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { ADDRESS, ASSET, NETWORK } from './payment.mjs';

// No private key is accepted. An external test wallet signs typedData with
// eth_signTypedData_v4. The request nonce is required by this pilot's binding.
export function signingBundle(challenge, payer, now = Math.floor(Date.now()/1000)) {
  const r = challenge.accepts?.[0], info = challenge.extensions?.['mctl-request-binding']?.info;
  if (r?.scheme !== 'exact' || r.network !== NETWORK || r.asset !== ASSET ||
      r.amount !== '10000' || !ADDRESS.test(r.payTo) || !ADDRESS.test(payer) ||
      !/^0x[0-9a-f]{64}$/.test(info?.nonce) || info.expires <= now) throw Error('Unsupported challenge');
  const authorization = { from:payer,to:r.payTo,value:r.amount,validAfter:String(now-1),
    validBefore:String(info.expires),nonce:info.nonce };
  return { request_id:info.requestId, typedData:{
    domain:{name:'USDC',version:'2',chainId:84532,verifyingContract:ASSET},
    types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},
      {name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],
      TransferWithAuthorization:[{name:'from',type:'address'},{name:'to',type:'address'},
        {name:'value',type:'uint256'},{name:'validAfter',type:'uint256'},
        {name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}]},
    primaryType:'TransferWithAuthorization',message:authorization },
    payment:{x402Version:2,resource:challenge.resource,accepted:r,
      payload:{signature:'REPLACE_WITH_EXTERNAL_TEST_WALLET_SIGNATURE',authorization}} };
}

async function rpc(params, env) {
  const url = new URL(env.MCTL_X402_PILOT_URL || 'http://127.0.0.1:8787/mcp');
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/mcp' || url.search || url.hash) {
    throw Error('Buyer CLI is loopback-only; remote client testing is a separate reviewed setup');
  }
  const response = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',
    Authorization:`Bearer ${env.MCTL_X402_PILOT_TOKEN}`},signal:AbortSignal.timeout(60000),
    body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params})});
  if (!response.ok) throw Error('Pilot request failed');
  const value = await response.json();
  if (value.error) throw Error('Pilot RPC failed');
  return value.result;
}
export async function buyer(argv,env=process.env) {
  const [mode,endpointID,path] = argv;
  if (!['prepare','send'].includes(mode) || !endpointID || !path) throw Error('Use prepare|send ENDPOINT_ID BUNDLE_PATH');
  if (mode === 'prepare') {
    const result = await rpc({name:'mctl_mcp_check',arguments:{endpoint_id:endpointID,request_id:randomUUID()}},env);
    const bundle = signingBundle(result.structuredContent,env.MCTL_X402_PILOT_PAYER);
    writeFileSync(path,JSON.stringify(bundle,null,2)+'\n',{mode:0o600,flag:'wx'});
    return { bundle:path,expires:result.structuredContent.extensions['mctl-request-binding'].info.expires };
  }
  const bundle = JSON.parse(readFileSync(path,'utf8'));
  return rpc({name:'mctl_mcp_check',arguments:{endpoint_id:endpointID,request_id:bundle.request_id},
    _meta:{'x402/payment':bundle.payment}},env);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  buyer(process.argv.slice(2)).then(r=>console.log(JSON.stringify(r,null,2)))
    .catch(()=>{console.error('Buyer failed; check loopback pilot, challenge expiry and signed bundle');process.exitCode=1;});
}
