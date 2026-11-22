/* Original fictional fixture author. Never writes or exports private keys. MIT. */
'use strict';
const {generateKeyPairSync,sign,X509Certificate,createHash}=require('node:crypto');
const fs=require('node:fs'),path=require('node:path');
const bytes=(...a)=>Buffer.concat(a.map(x=>Buffer.from(x)));
function tlv(tag,content){const b=Buffer.from(content),len=b.length<128?Buffer.from([b.length]):(()=>{let n=b.length,a=[];while(n){a.unshift(n&255);n>>>=8;}return Buffer.from([128|a.length,...a]);})();return bytes([tag],len,b);}
const seq=(...x)=>tlv(48,bytes(...x)),set=(...x)=>tlv(49,bytes(...x)),utf=s=>tlv(12,Buffer.from(s)),oct=b=>tlv(4,b),bit=b=>tlv(3,bytes([0],b));
function oid(s){const a=s.split('.').map(BigInt);const out=[];for(const v0 of [a[0]*40n+a[1],...a.slice(2)]){let v=v0,part=[Number(v&127n)];while((v>>=7n)>0n)part.unshift(Number(v&127n)|128);out.push(...part);}return tlv(6,out);}
function int(n){n=BigInt(n);let a=[];do{a.unshift(Number(n&255n));n>>=8n;}while(n);if(a[0]&128)a.unshift(0);return tlv(2,a);}
const dn=s=>seq(set(seq(oid('2.5.4.3'),utf(s))),set(seq(oid('2.5.4.10'),utf('Fictional Offline Lab'))));
function make(options={}){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const algorithm=seq(oid('1.3.101.112')),subject=dn(options.subject||'Offline Demo CA'),issuer=dn(options.issuer||options.subject||'Offline Demo CA');
 const extension=(id,value,critical=false)=>seq(oid(id),...(critical?[tlv(1,[255])]:[]),oct(value));
 const san=seq(tlv(130,Buffer.from('demo.invalid')),tlv(130,Buffer.from('*.example.invalid')),tlv(135,[192,0,2,42]),tlv(135,[0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1]));
 const ca=options.ca!==false;
 const extensions=seq(extension('2.5.29.19',seq(...(ca?[tlv(1,[255]),int(2)]:[])),true),
  extension('2.5.29.15',tlv(3,ca?[1,134]:[5,160]),true),
  extension('2.5.29.37',seq(oid('1.3.6.1.5.5.7.3.1'),oid('1.3.6.1.5.5.7.3.2'))),
  extension('2.5.29.17',san));
 const tbs=seq(tlv(160,int(2)),int(options.serial||42),algorithm,issuer,
  seq(tlv(23,Buffer.from(options.notBefore||'250101000000Z')),tlv(24,Buffer.from(options.notAfter||'20350101000000Z'))),
  subject,publicKey.export({type:'spki',format:'der'}),tlv(163,extensions));
 const der=seq(tbs,algorithm,bit(sign(null,tbs,privateKey)));
 const pem='-----BEGIN CERTIFICATE-----\n'+der.toString('base64').match(/.{1,64}/g).join('\n')+'\n-----END CERTIFICATE-----\n';
 return {der,pem};
}
if(require.main===module){
 const base=path.join(__dirname,'certinspect','fixtures');
 for(const [file,opts] of [['demo-ca',{}],['demo-other',{subject:'Other Fictional CA',serial:256}]]){
  const f=make(opts),native=new X509Certificate(f.der);if(!native.verify(native.publicKey))throw Error('Fixture must self-verify');
  fs.writeFileSync(path.join(base,file+'.der'),f.der);fs.writeFileSync(path.join(base,file+'.pem'),f.pem);
 }
}
module.exports={tlv,seq,set,utf,oid,int,dn,make};
