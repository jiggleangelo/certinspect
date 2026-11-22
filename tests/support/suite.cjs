const oracleSpawn=require('../oracle.cjs');
/* Original tests: independent SQLite / native crypto oracles and seeded grammar cases. MIT. */
'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto'),cp=require('node:child_process');
const S=require('./sqlschema/core.js'),C=require('./certinspect/core.js'),B=require('./generate-fixtures.cjs');
const pem=fs.readFileSync(__dirname+'/certinspect/fixtures/demo-ca.pem','utf8'),der=fs.readFileSync(__dirname+'/certinspect/fixtures/demo-ca.der'),other=fs.readFileSync(__dirname+'/certinspect/fixtures/demo-other.pem','utf8');
let seed=0x89cafe;function rand(n){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;}
function has(schema,code){return S.lint(schema).some(x=>x.code===code);}
test('fixture is an actually self-signed public Ed25519 certificate; native oracle',async()=>{
 const x=new crypto.X509Certificate(der),c=await C.inspect(pem,'2030-01-01T00:00:00Z'),p=c.certificates[0];
 assert(x.verify(x.publicKey));assert.equal(x.serialNumber,p.serial);assert.equal(x.fingerprint256.replace(/:/g,''),p.fingerprint);assert(x.subject.includes('CN=Offline Demo CA'));assert.equal(p.notBefore,new Date(x.validFrom).toISOString());assert.equal(p.notAfter,new Date(x.validTo).toISOString());
 assert.deepEqual(p.san,[{type:'DNS',value:'demo.invalid'},{type:'DNS',value:'*.example.invalid'},{type:'IP',value:'192.0.2.42'},{type:'IP',value:'2001:db8::1'}]);
 assert.deepEqual(p.keyUsage,['digitalSignature','keyCertSign','cRLSign']);assert.equal(p.extendedKeyUsage.length,2);assert.deepEqual(p.basicConstraints,{ca:true,pathLen:'2'});assert.equal(c.chain.issues.length,0);
});
test('both retained certificates self-verify and DER=PEM',()=>{
 for(const n of ['demo-ca','demo-other']){const d=fs.readFileSync(__dirname+'/certinspect/fixtures/'+n+'.der'),p=fs.readFileSync(__dirname+'/certinspect/fixtures/'+n+'.pem','utf8'),x=new crypto.X509Certificate(d);assert(x.verify(x.publicKey));assert.deepEqual(Buffer.from(C.inputs(p)[0]),d);assert.deepEqual(C.certificate(d),C.certificate(C.inputs(p)[0]));}
});
for(let i=0;i<120;i++)test('native SHA-256 oracle '+i,async()=>{
 const n=i<70?i:rand(10000),b=Uint8Array.from({length:n},()=>rand(256)),want=crypto.createHash('sha256').update(b).digest('hex').toUpperCase();assert.equal(C.sha256(b),want);assert.equal(await C.fingerprint(b,null),want);assert.equal(await C.fingerprint(b,crypto.webcrypto.subtle),want);
});
for(let i=0;i<der.length;i++)test('DER truncation fails atomically '+i,()=>assert.throws(()=>C.certificate(der.subarray(0,i))));
const malformedDER=[
 [],[48,128,0,0],[48,129,0],[48,130,0,128],[48,1,0],[48,2,0,0],
 [2,2,0,1],[2,2,255,255],[1,1,1],[1,2,0,0],[3,1,8],[3,2,3,7],[5,1,0],[31,1,0],[31,128,31,0],[48,0,0],[16,0],[36,0],
 [49,6,2,1,2,2,1,1],[48,255,1,2,3,4]
];
malformedDER.forEach((a,i)=>test('strict DER malformed '+i,()=>assert.throws(()=>C.der(Uint8Array.from(a)))));
test('DER input/node/depth bounds',()=>{assert.throws(()=>C.der(new Uint8Array(1048577)));let b=B.int(1);for(let i=0;i<34;i++)b=B.seq(b);assert.throws(()=>C.der(b));assert.throws(()=>C.der(B.seq(...Array.from({length:20001},()=>B.int(1)))));});
for(const id of ['0.0','1.39','2.40','2.999','2.999.1234567890123456789012345','1.3.6.1.5.5.7.3.1'])test('OID big integer roundtrip '+id,()=>assert.equal(C.oid(C.der(B.oid(id))),id));
for(const a of [[6,0],[6,1,128],[6,2,128,0],[6,1,255]])test('malformed OID '+a,()=>assert.throws(()=>C.oid(C.der(Uint8Array.from(a)))));
test('Unicode directory string decoding is exact',()=>{
 assert.equal(C.string(C.der(B.utf('Δ <img> 🪴'))),'Δ <img> 🪴');assert.equal(C.string(C.der(B.tlv(30,[0,65,3,0x94]))),'AΔ');assert.equal(C.string(C.der(B.tlv(28,[0,1,0xf3,0x31]))),'🌱');
 for(const b of [B.tlv(12,[0xff]),B.tlv(30,[0]),B.tlv(30,[0xd8,0]),B.tlv(28,[0,0x11,0,0]),B.tlv(19,[64]),B.tlv(22,[255]),B.tlv(18,[65])])assert.throws(()=>C.string(C.der(b)));
});
test('certificate structural mutations reject',()=>{
 const tree=C.der(der),tbs=tree.children[0],a=tbs.children;
 const outer=parts=>B.seq(B.seq(...parts),tree.children[1].encoded,tree.children[2].encoded);
 const entries=a.map(x=>x.encoded);
 for(const mut of [
  entries.slice(1), // wrong field interpretation v1+extensions
  entries.map((x,i)=>i===0?B.tlv(160,B.int(0)):x),
  entries.map((x,i)=>i===1?B.int(0):x),
  entries.map((x,i)=>i===1?B.tlv(2,[255]):x),
  entries.map((x,i)=>i===2?B.seq(B.oid('1.2.3')):x),
  entries.map((x,i)=>i===4?B.seq(B.tlv(23,Buffer.from('350101000000Z')),B.tlv(23,Buffer.from('250101000000Z'))):x),
  [...entries,entries.at(-1)]
 ])assert.throws(()=>C.certificate(outer(mut)));
 assert.throws(()=>C.certificate(B.seq(...tree.children.map(x=>x.encoded),B.int(1))));
});
test('extension duplicate, critical-default and malformed SAN/BC fail',()=>{
 const tree=C.der(der),a=tree.children[0].children.map(x=>x.encoded);
 const extension=(id,value,critical)=>B.seq(B.oid(id),...(critical!==undefined?[B.tlv(1,[critical])]:[]),B.tlv(4,value));
 const original=C.der(a.at(-1)).children[0].children.map(x=>x.encoded);
 function replace(exts){return B.seq(B.seq(...a.slice(0,-1),B.tlv(163,B.seq(...exts))),tree.children[1].encoded,tree.children[2].encoded);}
 for(const exts of [[...original,original[0]],[extension('2.5.29.19',B.seq(),0)],[extension('2.5.29.19',B.seq(B.int(1)))],[extension('2.5.29.19',B.seq(B.tlv(1,[0])))],[extension('2.5.29.17',B.seq(B.tlv(135,[1,2,3])))],[extension('2.5.29.17',B.seq(B.tlv(130,[255])))],[extension('2.5.29.37',B.seq())],[extension('2.5.29.15',B.tlv(3,[0,0,1]))]])assert.throws(()=>C.certificate(replace(exts)));
 const c=C.certificate(replace([extension('1.2.3.4',B.seq(),255)]));assert(c.notes.some(n=>n.includes('Unrecognized critical')));
});
test('X.509 UTC/Generalized time calendar and pivot',()=>{
 const utc=s=>C.time(C.der(B.tlv(23,Buffer.from(s)))),gen=s=>C.time(C.der(B.tlv(24,Buffer.from(s))));
 assert.equal(utc('491231235959Z'),'2049-12-31T23:59:59.000Z');assert.equal(utc('500101000000Z'),'1950-01-01T00:00:00.000Z');assert.equal(gen('20500228000000Z'),'2050-02-28T00:00:00.000Z');assert.equal(utc('240229000000Z'),'2024-02-29T00:00:00.000Z');
 for(const s of ['230229000000Z','250001000000Z','250132000000Z','250101240000Z','250101006000Z','250101000060Z','2501010000Z','250101000000+0000'])assert.throws(()=>utc(s));
});
test('reference UTC validation and inclusive time boundaries',()=>{
 const c=C.certificate(der);for(const s of ['','2030-02-30T00:00:00Z','2030-01-01','2030-01-01T00:00:00+00:00','2030-01-01T24:00Z','not a date'])assert.throws(()=>C.validity(c,s));
 assert.equal(C.validity(c,c.notBefore).status,'valid-at-reference');assert.equal(C.validity(c,c.notAfter).status,'valid-at-reference');assert.equal(C.validity(c,'2024-12-31T23:59:59Z').status,'not-yet-valid');assert.equal(C.validity(c,'2035-01-01T00:00:01Z').secondsUntilExpiry,-1);assert.equal(C.validity(c,'2035-01-01T00:00:01Z').status,'expired');assert.equal(C.reference('2030-01-01T00:00Z'),Date.parse('2030-01-01T00:00:00Z'));
});
for(const [a,want] of [[[0,0,0,0],'0.0.0.0'],[Array(16).fill(0),'::'],[[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1],'2001:db8::1'],[[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1],'::1:0:0:0:1']])test('SAN IP formatter '+want,()=>assert.equal(C.ip(Uint8Array.from(a)),want));
test('strict PEM grammar, quotas and padding',()=>{
 assert.equal(C.inputs(pem+other).length,2);
 for(const s of ['',pem+'garbage','garbage'+pem,pem.replace('END CERTIFICATE','END PRIVATE KEY'),('-----BEGIN '+'PRIVATE KEY-----\nAAAA\n-----END '+'PRIVATE KEY-----'),pem.repeat(17),'x'.repeat(1500001),'-----BEGIN CERTIFICATE-----\nAB==\n-----END CERTIFICATE-----','-----BEGIN CERTIFICATE-----\nAAB=\n-----END CERTIFICATE-----','-----BEGIN CERTIFICATE-----\nAAAA=\n-----END CERTIFICATE-----'])assert.throws(()=>C.inputs(s));
});
test('chain order, duplicate, missing issuer, CA, usage, path length',async()=>{
 const report=await C.inspect(pem+other,'2030-01-01T00:00:00Z');assert(report.chain.issues.some(i=>i.code==='ORDER_MISMATCH'));assert(report.chain.issues.some(i=>i.code==='SELF_ISSUED_NOT_LAST'));
 assert((await C.inspect(pem+pem,'2030-01-01T00:00:00Z')).chain.issues.some(i=>i.code==='DUPLICATE'));
 const cert=(subject,issuer,ca,pathLen=null)=>({subject:{canonical:subject},issuer:{canonical:issuer},selfIssued:subject===issuer,basicConstraints:{ca,pathLen},keyUsage:['keyCertSign'],extensions:[{oid:'2.5.29.15'}]});
 const leaf=cert('leaf','intermediate',false),inter=cert('intermediate','root',true),root=cert('root','root',true,'1');
 assert.deepEqual(C.chain([leaf,inter,root]).issues,[]);assert(C.chain([root,inter,leaf]).issues.some(i=>i.code==='ORDER_MISMATCH'));assert(C.chain([leaf]).issues.some(i=>i.code==='INCOMPLETE_CHAIN'));
 root.basicConstraints.pathLen='0';assert(C.chain([leaf,inter,root]).issues.some(i=>i.code==='PATH_LENGTH'));inter.basicConstraints.ca=false;inter.keyUsage=[];assert(C.chain([leaf,inter,root]).issues.some(i=>i.code==='ISSUER_NOT_CA'));assert(C.chain([leaf,inter,root]).issues.some(i=>i.code==='ISSUER_KEY_USAGE'));assert.throws(()=>C.chain([]));
});
for(let i=0;i<100;i++)test('generated PostgreSQL schema independent model '+i,()=>{
 const count=1+rand(12),cols=Array.from({length:count},(_,j)=>({name:'col_'+j,type:['INT','BIGINT','TEXT','VARCHAR(40)','NUMERIC(12,2)','TIMESTAMP WITH TIME ZONE'][rand(6)],nn:!!rand(2)}));
 const sql='/* fiction */ CREATE TABLE "Table '+i+'" ("id" BIGINT PRIMARY KEY, '+cols.map(c=>c.name+' '+c.type+(c.nn?' NOT NULL':'')).join(', ')+', UNIQUE('+cols[0].name+'));';
 const t=S.parse(sql).tables[0];assert.equal(t.name,'Table '+i);assert.equal(t.columns.length,count+1);assert.deepEqual(t.primaryKey,['id']);assert.deepEqual(t.unique,[[cols[0].name]]);
 for(let j=0;j<count;j++){assert.equal(t.columns[j+1].name,cols[j].name);assert.equal(t.columns[j+1].type,cols[j].type);assert.equal(t.columns[j+1].notNull,cols[j].nn);}
});
test('SQLite independent in-memory PRAGMA oracle, no DB file',()=>{
 const ddl="CREATE TABLE parent(id INTEGER PRIMARY KEY, label TEXT UNIQUE NOT NULL); CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER, note VARCHAR(40) DEFAULT 'x,y', FOREIGN KEY(parent_id) REFERENCES parent(id)); CREATE INDEX child_parent ON child(parent_id);";
 const script="import sqlite3,json,sys\ndb=sqlite3.connect(':memory:');db.executescript(sys.stdin.read());print(json.dumps({n:[list(x) for x in db.execute('pragma table_info('+n+')')] for n in ['parent','child']}))";
 const p=oracleSpawn('python3',['-B','-c',script],{input:ddl,encoding:'utf8'});assert.equal(p.status,0,p.stderr);const oracle=JSON.parse(p.stdout),schema=S.parse(ddl,'sqlite');
 for(const t of schema.tables)for(let i=0;i<t.columns.length;i++){const c=t.columns[i],n=oracle[t.name][i];assert.equal(c.name,n[1]);assert.equal(c.type,n[2]);assert.equal(c.notNull,!!n[3]);assert.equal(c.primaryKey,!!n[5]);}
 assert(!has(schema,'UNINDEXED_FK'));
});
test('composite PK/FK UNIQUE and explicit indexes',()=>{
 const a=S.parse('CREATE TABLE p(a INT,b INT,CONSTRAINT pk PRIMARY KEY(a,b)); CREATE TABLE c(x INT,y INT,UNIQUE(x,y),FOREIGN KEY(x,y) REFERENCES p);');
 assert.deepEqual(a.tables[0].primaryKey,['a','b']);assert.deepEqual(a.tables[1].foreignKeys[0].refColumns,['a','b']);assert(!has(a,'UNINDEXED_FK'));assert(!has(a,'NON_UNIQUE_TARGET'));
});
const fkBase='CREATE TABLE p(a INT PRIMARY KEY,b INT UNIQUE); CREATE TABLE c(x INT,y INT,FOREIGN KEY(x) REFERENCES p(a));';
for(const [suffix,indexed] of [['',false],['CREATE INDEX ix ON c(x);',true],['CREATE INDEX ix ON c(x,y);',true],['CREATE INDEX ix ON c(y,x);',false],['CREATE INDEX ix ON c(x) WHERE x > 0;',false],['CREATE INDEX ix ON c((x));',false],['CREATE INDEX ix ON c USING hash(x);',false],['CREATE UNIQUE INDEX ix ON c(x DESC);',true]])test('leading full FK index coverage '+suffix,()=>assert.equal(!has(S.parse(fkBase+suffix),'UNINDEXED_FK'),indexed));
test('schema qualified and quoted identifiers, string/comments stay inert',()=>{
 const s=S.parse('CREATE TABLE app."Parent"("Id" INT PRIMARY KEY); CREATE TABLE app.child (id INT PRIMARY KEY, p INT REFERENCES "Parent"("Id"), "x<script>" TEXT DEFAULT $$); DROP TABLE app.child;$$); CREATE INDEX ix ON app.child(p);');
 assert.equal(s.tables.length,2);assert.equal(s.tables[1].foreignKeys[0].table,'app.Parent');assert(!has(s,'MISSING_TARGET'));assert(!has(s,'UNINDEXED_FK'));assert(S.markdown(s).includes('&lt;script&gt;'));
 const sqlite=S.parse('CREATE TABLE [T]([X] INTEGER PRIMARY KEY, `y` TEXT DEFAULT \'a,);--\');','sqlite');assert.equal(sqlite.tables[0].columns[0].key,'x');
});
for(const [ddl,code] of [
 ['CREATE TABLE x(a INT);','MISSING_PK'],
 ['CREATE TABLE x(a INT REFERENCES absent);','MISSING_TARGET'],
 ['CREATE TABLE p(a INT); CREATE TABLE x(a INT REFERENCES p(z));','MISSING_TARGET_COLUMN'],
 ['CREATE TABLE p(a INT,b INT,PRIMARY KEY(a,b)); CREATE TABLE x(a INT REFERENCES p);','FK_ARITY'],
 ['CREATE TABLE p(a INT); CREATE TABLE x(a INT REFERENCES p(a));','NON_UNIQUE_TARGET']
])test('lint '+code,()=>assert(has(S.parse(ddl),code)));
test('PK/UNIQUE index referenced coverage, defaults/check/generated',()=>{
 const s=S.parse("CREATE TABLE p(a INT);CREATE UNIQUE INDEX p_a ON p(a);CREATE TABLE c(id INT PRIMARY KEY,x INT NOT NULL REFERENCES p(a) ON DELETE CASCADE, d NUMERIC(8,2) DEFAULT -1.2, n TEXT DEFAULT now()::text, a INT GENERATED ALWAYS AS (id+1) STORED,CHECK(id>0));CREATE INDEX c_x ON c(x);");assert(!has(s,'NON_UNIQUE_TARGET'));assert(!has(s,'UNINDEXED_FK'));assert.equal(s.tables[1].columns[2].type,'NUMERIC(8,2)');
});
for(const [from,to,narrow] of [
 ['BIGINT','INTEGER',true],['INTEGER','SMALLINT',true],['INT2','INT8',false],['VARCHAR(120)','VARCHAR(60)',true],['TEXT','VARCHAR(1)',true],['VARCHAR(5)','TEXT',false],['NUMERIC(10,2)','NUMERIC(8,2)',true],['NUMERIC(10,2)','NUMERIC(10,3)',true],['NUMERIC(10,2)','NUMERIC(12,3)',false],['NUMERIC','DECIMAL(5,2)',true],['DOUBLE PRECISION','REAL',true],['TEXT','INT',false]
])test('migration type classification '+from+' -> '+to,()=>{
 const before=S.parse('CREATE TABLE x(id INT PRIMARY KEY,c '+from+');'),after=S.parse('CREATE TABLE x(id INT PRIMARY KEY,c '+to+');'),d=S.diff(before,after);assert.equal(d.some(x=>x.code==='TYPE_NARROWING'),narrow);assert.equal(d.length,1);
});
test('migration additions/drops/nullability/keys and no alias renames',()=>{
 const a=S.parse('CREATE TABLE x(id INT PRIMARY KEY,a TEXT,b INT NOT NULL); CREATE TABLE gone(id INT);'),b=S.parse('CREATE TABLE x(id INT PRIMARY KEY,b INT,c TEXT NOT NULL,UNIQUE(b));CREATE TABLE added(id INT);'),codes=S.diff(a,b).map(x=>x.code);
 for(const code of ['DROP_TABLE','DROP_COLUMN','ADD_COLUMN','ADD_TABLE','DROP_NOT_NULL','KEY_CHANGE'])assert(codes.includes(code));
 assert.deepEqual(S.diff(a,a),[]);assert.throws(()=>S.diff(a,S.parse('CREATE TABLE x(id INT);','sqlite')));
 assert.equal(S.diff(S.parse('CREATE TABLE x(a VARCHAR(10));','sqlite'),S.parse('CREATE TABLE x(a VARCHAR(5));','sqlite'))[0].code,'TYPE_CHANGE');
});
const badSQL=['','SELECT 1','ALTER TABLE x ADD y INT','CREATE TABLE x AS SELECT 1','CREATE TABLE x()','CREATE TABLE x(id);','CREATE TABLE x(id INT,);','CREATE TABLE x(id INT,,x TEXT);','CREATE TABLE x(id INT PRIMARY KEY,PRIMARY KEY(id));','CREATE TABLE x(id INT,id TEXT);','CREATE TABLE x(id INT,PRIMARY KEY(no));','CREATE TABLE x(id INT,PRIMARY KEY(id,id));','CREATE TABLE x(id INT,UNIQUE(id,id));','CREATE TABLE x(id INT,UNIQUE(no));','CREATE TABLE x(id INT,FOREIGN KEY(id) REFERENCES p(a,b));','CREATE TABLE x(id INT) ENGINE=foo;','CREATE TABLE x(id INT weirdclause BAD NOT NULL); CREATE TABLE x(id INT);',"CREATE TABLE x(id TEXT DEFAULT 'unterminated);",'/* unclosed','CREATE TABLE "x(id INT);','CREATE TABLE x(id INT DEFAULT);','CREATE TABLE x(id INT NOT MISSING);','CREATE TABLE x(id INT) ; DROP TABLE x;','CREATE INDEX x ON y(id);'];
badSQL.forEach((s,i)=>test('malformed/unsupported SQL '+i,()=>assert.throws(()=>S.parse(s))));
test('SQLite typeless / STRICT / WITHOUT ROWID are explicit subset',()=>{assert.equal(S.parse('CREATE TABLE x(a);','sqlite').tables[0].columns[0].type,'(unspecified)');assert(S.parse('CREATE TABLE x(a INTEGER PRIMARY KEY) STRICT, WITHOUT ROWID;','sqlite'));});
test('DDL size/token/table/nesting limits',()=>{
 assert.throws(()=>S.parse('x'.repeat(500001)));assert.throws(()=>S.tokenize('x '.repeat(80001)));assert.throws(()=>S.parse(Array.from({length:151},(_,i)=>'CREATE TABLE t'+i+'(id INT);').join('')));assert.throws(()=>S.parse('CREATE TABLE x(a INT DEFAULT '+'('.repeat(65)+'1'+')'.repeat(65)+');'));
});
test('Markdown escapes HTML, pipes, newlines and JSON is exact',()=>{
 const s=S.parse('CREATE TABLE "a|<img>\n"("c|<svg>" TEXT UNIQUE);');const m=S.markdown(s);assert(!m.includes('<img>'));assert(m.includes('&#124;'));assert.deepEqual(JSON.parse(JSON.stringify(s)),s);
});
test('source security and offline contracts',()=>{
 for(const tool of ['sqlschema','certinspect']){
  const html=fs.readFileSync(__dirname+'/'+tool+'/index.html','utf8'),app=fs.readFileSync(__dirname+'/'+tool+'/app.js','utf8'),core=fs.readFileSync(__dirname+'/'+tool+'/core.js','utf8'),css=fs.readFileSync(__dirname+'/'+tool+'/style.css','utf8');
  assert(html.includes("connect-src 'none'"));assert(html.includes("default-src 'none'"));assert(!/https?:|<iframe|<form|onload=|onclick=/i.test(html.replace(/href="https:\/\/(?:manykiln\.com\/(?:tools\/(?:certinspect|sqlschema)\/|privacy)|github\.com\/jiggleangelo\/(?:certinspect|sqlschema)|join\.manykiln\.com\/\?from=(?:certinspect|sqlschema))"/g,'')));assert(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage/.test(app+core));assert(!/@import|url\s*\(/i.test(css));assert(app.includes('textContent'));
 }
});

test('quoted custom type case retained and same-schema FK resolution preferred',()=>{
 const a=S.parse('CREATE TABLE p(id INT PRIMARY KEY);CREATE TABLE app.p(id BIGINT PRIMARY KEY);CREATE TABLE app.c(id INT PRIMARY KEY,x BIGINT REFERENCES p(id),custom "CamelType");');
 assert.equal(a.tables[2].foreignKeys[0].table,'app.p');assert.equal(a.tables[2].columns[2].type,'"CamelType"');
 const b=S.parse('CREATE TABLE x(v "lowerType");');assert.equal(b.tables[0].columns[0].type,'"lowerType"');
});
test('invalid index columns cannot mask missing FK coverage',()=>{
 const s=S.parse(fkBase+'CREATE INDEX ix ON c(x,missing);');assert(has(s,'UNINDEXED_FK'));assert(s.notes.some(x=>x.includes('absent column')));
});
test('certificate fingerprint falls back after SubtleCrypto rejection',async()=>{
 assert.equal(await C.fingerprint(der,{digest:async()=>{throw Error('disabled');}}),C.sha256(der));
});
test('name matching normalizes attributes within a multivalue RDN, retains RDN order',()=>{
 const a=C.name(C.der(B.seq(B.set(B.seq(B.oid('2.5.4.3'),B.utf('  DEMO   CA '))))));
 const b=C.name(C.der(B.seq(B.set(B.seq(B.oid('2.5.4.3'),B.utf('demo ca'))))));
 assert.equal(a.canonical,b.canonical);
});

// Hydrogen F1: PostgreSQL array punctuation must not become SQLite identifiers.
for(const [input,want] of [
 ['TEXT[]','TEXT[]'],['INT[3]','INT[3]'],['VARCHAR(20)[]','VARCHAR(20)[]'],
 ['NUMERIC(10,2)[][]','NUMERIC(10,2)[][]'],['text [ ]','TEXT[]'],
 ['numeric (10, 2) [3] [4]','NUMERIC(10,2)[3][4]'],['"CamelType"[]','"CamelType"[]']
])test('F1 exact PostgreSQL array type '+input,()=>{
 const s=S.parse('CREATE TABLE t(id INT PRIMARY KEY, v '+input+' NOT NULL UNIQUE);','postgres');
 assert.equal(s.tables[0].columns[1].type,want);assert(s.tables[0].columns[1].notNull);assert(s.tables[0].columns[1].unique);
 assert(S.markdown(s).includes('| v | '+want+' |'));assert.deepEqual(S.diff(s,s),[]);
});
test('F1 dialect-aware brackets preserve SQLite quoted identifiers and types',()=>{
 assert.deepEqual(S.tokenize('TEXT[]').map(t=>[t.kind,t.value]),[['word','TEXT'],['symbol','['],['symbol',']']]);
 assert.deepEqual(S.tokenize('[odd,name]','sqlite').map(t=>[t.kind,t.value]),[['id','odd,name']]);
 const s=S.parse('CREATE TABLE [odd,table]([id] INTEGER PRIMARY KEY,[NOT] [Text],[x] TEXT REFERENCES [odd,table]([id]) ON DELETE SET NULL);','sqlite');
 assert.equal(s.tables[0].name,'odd,table');assert.equal(s.tables[0].columns[1].name,'NOT');assert.equal(s.tables[0].columns[1].type,'"Text"');
 assert.deepEqual(s.tables[0].foreignKeys[0].columns,['x']);
 assert.throws(()=>S.parse('CREATE TABLE [t]([id] INT);','postgres'));
});
for(const [from,to,code] of [
 ['TEXT[]','VARCHAR(20)[]','TYPE_NARROWING'],['VARCHAR(20)[]','TEXT[]','TYPE_CHANGE'],
 ['INT[3]','SMALLINT[]','TYPE_NARROWING'],['INT[]','BIGINT[3]','TYPE_CHANGE'],
 ['NUMERIC(10,2)[][]','NUMERIC(8,2)[]','TYPE_NARROWING'],
 ['NUMERIC(10,2)[][]','NUMERIC(10,3)[][]','TYPE_NARROWING'],
 ['NUMERIC(10,2)[]','NUMERIC(12,3)[][]','TYPE_CHANGE'],
 ['INT[3]','INT[]','TYPE_CHANGE'],['TEXT','VARCHAR(20)[]','TYPE_CHANGE'],
 ['TEXT[]','VARCHAR(20)','TYPE_CHANGE']
])test('F1 array diff '+from+' -> '+to,()=>{
 const make=type=>S.parse('CREATE TABLE t(v '+type+');','postgres');
 const d=S.diff(make(from),make(to));assert.equal(d.length,1);assert.equal(d[0].code,code);
 assert(d[0].message.includes(from+' → '+to));
 assert.equal(S.typeInfo(from).array,from.includes('[')?true:undefined);
});

// Hydrogen F2: consume complete FK suffixes, then resume real column constraints.
const deferrability=['','DEFERRABLE','NOT DEFERRABLE','DEFERRABLE INITIALLY DEFERRED','DEFERRABLE INITIALLY IMMEDIATE','NOT DEFERRABLE INITIALLY DEFERRED','NOT DEFERRABLE INITIALLY IMMEDIATE'];
for(const dialect of ['postgres','sqlite'])for(const event of ['DELETE','UPDATE'])for(const action of ['CASCADE','RESTRICT','NO ACTION','SET NULL','SET DEFAULT'])for(const defer of deferrability){
 test('F2 '+dialect+' ON '+event+' '+action+' '+defer,()=>{
  const ddl='CREATE TABLE p(id INT PRIMARY KEY); CREATE TABLE c(id INT PRIMARY KEY, p_id INT DEFAULT 1 REFERENCES p(id) MATCH SIMPLE ON '+event+' '+action+' '+defer+' NOT NULL UNIQUE CHECK(p_id>0));';
  const s=S.parse(ddl,dialect),c=s.tables[1].columns[1],f=s.tables[1].foreignKeys[0];
  assert.equal(c.type,'INT');assert.equal(c.notNull,true);assert.equal(c.unique,true);
  assert.deepEqual(f.columns,['p_id']);assert.deepEqual(f.refColumns,['id']);assert.equal(f.table,'p');
  assert(!has(s,'MISSING_TARGET'));assert(!has(s,'NON_UNIQUE_TARGET'));assert.deepEqual(S.diff(s,s),[]);
 });
}
for(const match of ['SIMPLE','FULL','PARTIAL'])test('F2 combined actions / later DEFAULT / nullable / MATCH '+match,()=>{
 const s=S.parse('CREATE TABLE p(id INT PRIMARY KEY); CREATE TABLE c(id INT PRIMARY KEY,p_id INT REFERENCES p(id) MATCH '+match+' ON DELETE SET DEFAULT ON UPDATE SET NULL NOT DEFERRABLE INITIALLY IMMEDIATE DEFAULT 1 NULL UNIQUE,tail TEXT NOT NULL);');
 assert.equal(s.tables[1].columns[1].notNull,false);assert.equal(s.tables[1].columns[1].unique,true);
 assert.equal(s.tables[1].columns[2].notNull,true);assert.equal(s.tables[1].foreignKeys.length,1);
});
for(const suffix of ['ON','ON INSERT CASCADE','ON DELETE','ON DELETE SET','ON DELETE SET MISSING','ON UPDATE NO','MATCH','MATCH UNKNOWN','DEFERRABLE INITIALLY','NOT DEFERRABLE INITIALLY UNKNOWN'])test('F2 incomplete suffix rejected '+suffix,()=>{
 assert.throws(()=>S.parse('CREATE TABLE p(id INT PRIMARY KEY); CREATE TABLE c(p_id INT REFERENCES p(id) '+suffix+');'));
});
