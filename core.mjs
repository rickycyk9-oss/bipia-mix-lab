export const CONDITIONS=['en','zh','mixed_sentence','mixed_phrase'];
export const LABELS={en:'英文原文',zh:'中文翻译',mixed_sentence:'分句级混合',mixed_phrase:'词语级混合',clean:'无攻击对照'};
export function canonical(value){
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
export function parseJSONL(text){
  const rows=[];for(const [index,line]of text.replace(/^\uFEFF/,'').split(/\r?\n/).entries()){
    if(!line.trim())continue;let row;
    try{row=JSON.parse(line);}catch{throw new Error(`第 ${index+1} 行不是有效 JSON`);}
    if(!row||typeof row!=='object'||Array.isArray(row))throw new Error(`第 ${index+1} 行必须是 JSON 对象`);
    rows.push(row);
  }return rows;
}
export function expectedCounts(cases,positions,repeats=1){
  const clean=new Set(cases.map(c=>canonical([c.task,c.context_id,c.question,c.ideal]))).size;
  const attacked=cases.length*CONDITIONS.length*positions.length;
  return {attacked,clean,samples:attacked+clean,requests:(attacked+clean)*repeats};
}
export function readiness({cases=[],variants=[],connected=false,studyId=null,hasResults=false}){
  const ids=new Set(cases.map(c=>c.attack_id));
  const approved=new Set(variants.filter(v=>v.status==='approved'&&v.review?.digest).map(v=>v.attack_id));
  const reviewed=[...ids].filter(id=>approved.has(id)).length;
  const steps=[cases.length>0,ids.size>0&&reviewed===ids.size,connected,!!studyId,!!hasResults];
  return {reviewed,required:ids.size,steps,completed:steps.filter(Boolean).length,ready:steps.slice(0,3).every(Boolean)};
}
// Fallback supports HTTP-only private previews; localhost/HTTPS uses Web Crypto.
export async function sha256(text,subtle=globalThis.crypto?.subtle){
  const data=new TextEncoder().encode(text);
  if(subtle)return [...new Uint8Array(await subtle.digest('SHA-256',data))].map(v=>v.toString(16).padStart(2,'0')).join('');
  const k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const bytes=new Uint8Array(Math.ceil((data.length+9)/64)*64);bytes.set(data);bytes[data.length]=128;
  const view=new DataView(bytes.buffer);view.setUint32(bytes.length-8,Math.floor(data.length*8/4294967296));view.setUint32(bytes.length-4,data.length*8);
  const rr=(x,n)=>(x>>>n)|(x<<(32-n)),w=new Uint32Array(64);
  for(let offset=0;offset<bytes.length;offset+=64){
    for(let t=0;t<16;t++)w[t]=view.getUint32(offset+t*4);
    for(let t=16;t<64;t++){const x=w[t-15],y=w[t-2];w[t]=(w[t-16]+(rr(x,7)^rr(x,18)^(x>>>3))+w[t-7]+(rr(y,17)^rr(y,19)^(y>>>10)))>>>0;}
    let [a,b,c,d,e,f,g,z]=h;
    for(let t=0;t<64;t++){const first=(z+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+k[t]+w[t])>>>0,second=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;z=g;g=f;f=e;e=(d+first)>>>0;d=c;c=b;b=a;a=(first+second)>>>0;}
    [a,b,c,d,e,f,g,z].forEach((v,i)=>h[i]=(h[i]+v)>>>0);
  }
  return h.map(v=>v.toString(16).padStart(8,'0')).join('');
}
export async function approvedVariant(row,reviewer){
  if(!reviewer.trim())throw new Error('请填写审核人姓名');
  if(!row.original||row.variants?.en!==row.original)throw new Error('英文基线必须与原始攻击完全一致');
  for(const c of CONDITIONS)if(typeof row.variants[c]!=='string'||!row.variants[c].trim())throw new Error('四种语言版本都不能为空');
  for(const literal of row.protected_literals||[])for(const c of CONDITIONS)if(!row.variants[c].includes(literal))throw new Error(`请保留字面量 ${literal}`);
  const keys=['attack_id','original','variants','success_criterion','protected_literals','evaluation'];
  const payload=Object.fromEntries(keys.map(k=>[k,row[k]??null]));
  const digest=await sha256(canonical(payload));
  return {...row,status:'approved',review:{reviewer:reviewer.trim(),time_utc:new Date().toISOString(),digest}};
}
export function resultRows(study,responses,scores){
  const samples=new Map(study.map(r=>[r.sample_id,r]));
  const predictions=new Map(responses.map(r=>[r.job_id,r]));
  const judgments=new Map(scores.map(r=>[r.job_id,r]));
  return [...predictions.values()].map(r=>({...samples.get(r.sample_id),...r,score:judgments.get(r.job_id)}));
}
export function percent(value){return typeof value==='number'&&Number.isFinite(value)?(value*100).toFixed(1)+'%':'—';}
export function escapeHTML(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
export function csv(rows){
  if(!rows.length)return '';const keys=Object.keys(rows[0]);
  const cell=v=>'"'+String(typeof v==='object'?JSON.stringify(v):v??'').replace(/"/g,'""')+'"';
  return [keys.map(cell).join(','),...rows.map(r=>keys.map(k=>cell(r[k])).join(','))].join('\r\n');
}

export function validateSummary(value){
 const bad=()=>{throw new Error('不是有效的实验汇总文件');};
 if(!value||!Array.isArray(value.groups))bad();
 const count=x=>Number.isSafeInteger(x)&&x>=0;
 for(const group of value.groups){
  if(!group||!['en','zh','mixed_sentence','mixed_phrase','clean'].includes(group.condition))bad();
  for(const [key,v]of Object.entries(group)){
   if(['condition','task','layout','defense'].includes(key))continue;
   if(key.endsWith('ci95')){if(v!==null&&(!Array.isArray(v)||v.length!==2||v.some(x=>typeof x!=='number'||!Number.isFinite(x))))bad();continue;}
   if(v!==null&&(typeof v!=='number'||!Number.isFinite(v)))bad();
  }
  if(group.asr!=null&&(group.asr<0||group.asr>1))bad();
  for(const key of ['expected','valid_attack_scores'])if(group[key]!==undefined&&!count(group[key]))bad();
 }
 if(value.total!==undefined&&(!value.total||Object.values(value.total).some(v=>!count(v))))bad();
 if(value.paired!==undefined&&!Array.isArray(value.paired))bad();
 for(const pair of value.paired||[]){
  if(!pair||!CONDITIONS.includes(pair.condition))bad();
  for(const key of ['n_complete_pairs','n_context_clusters'])if(pair[key]!==undefined&&!count(pair[key]))bad();
  if(pair.delta_asr_vs_en!=null&&(typeof pair.delta_asr_vs_en!=='number'||!Number.isFinite(pair.delta_asr_vs_en)||Math.abs(pair.delta_asr_vs_en)>1))bad();
 }
 return value;
}
