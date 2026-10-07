const $=s=>document.querySelector(s);
let running=false,stopFlag=false,total=0,done=0,startTime=0;

function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function hex(buf){return [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function md5(s){ // compact MD5 implementation for local lab use
 const r=[7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21],k=[];
 for(let i=0;i<64;i++)k[i]=Math.floor(Math.abs(Math.sin(i+1))*2**32)>>>0;
 let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
 const bytes=new TextEncoder().encode(s),n=(((bytes.length+8)>>6)+1)*16,x=new Uint32Array(n);
 for(let i=0;i<bytes.length;i++)x[i>>2]|=bytes[i]<<((i&3)*8);
 x[bytes.length>>2]|=0x80<<((bytes.length&3)*8); x[n-2]=bytes.length*8;
 for(let o=0;o<n;o+=16){let a=a0,b=b0,c=c0,d=d0;
  for(let i=0;i<64;i++){let f,g;
   if(i<16){f=(b&c)|(~b&d);g=i}else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)%16}else if(i<48){f=b^c^d;g=(3*i+5)%16}else{f=c^(b|~d);g=(7*i)%16}
   let q=(a+f+k[i]+x[o+g])>>>0,rr=r[(i>>4)*4+(i&3)],z=(q<<rr)|(q>>>(32-rr));a=d;d=c;c=b;b=(b+z)>>>0}
  a0=(a0+a)>>>0;b0=(b0+b)>>>0;c0=(c0+c)>>>0;d0=(d0+d)>>>0}
 return [a0,b0,c0,d0].map(v=>[0,8,16,24].map(s=>(v>>>s&255).toString(16).padStart(2,'0')).join('')).join('')
}
async function digest(type,s){if(type==='md5')return md5(s);let b=await crypto.subtle.digest(type.toUpperCase(),new TextEncoder().encode(s));return hex(b)}
function detect(h){let s=h.trim();if(/^\$2[aby]\$\d\d\$/.test(s))return ['bcrypt','not available'];if(/^[0-9a-fA-F]{32}$/.test(s))return ['md5','MD5'];if(/^[0-9a-fA-F]{40}$/.test(s))return ['sha1','SHA-1'];if(/^[0-9a-fA-F]{64}$/.test(s))return ['sha256','SHA-256'];if(/^[0-9a-fA-F]{128}$/.test(s))return ['sha512','SHA-512'];return ['unknown','Unknown']}
$("#detect").onclick=()=>{let [t,n]=detect($("#hash").value);$("#hashType").value=['md5','sha1','sha256','sha512'].includes(t)?t:'auto';$("#detected").textContent=n==='not available'?'bcrypt detected — this iPhone-only build does not implement bcrypt.':n==='Unknown'?'No confident match.':`Detected: ${n}`};
$("#mode").onchange=()=>{$("#dictBox").classList.toggle("hidden",$("#mode").value!=="dictionary");$("#maskBox").classList.toggle("hidden",$("#mode").value!=="mask")};
function candidatesFromMask(mask,limit){let chars={d:"0123456789",l:"abcdefghijklmnopqrstuvwxyz",u:"ABCDEFGHIJKLMNOPQRSTUVWXYZ",s:" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",a:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"};let parts=[];for(let i=0;i<mask.length;){if(mask[i]==='?'&&chars[mask[i+1]]){parts.push(chars[mask[i+1]]);i+=2}else{parts.push(mask[i]);i++}}let out=[],cur=Array(parts.length).fill("");function rec(i){if(out.length>=limit||stopFlag)return;if(i===parts.length){out.push(cur.join(""));return}for(const c of parts[i]){cur[i]=c;rec(i+1);if(out.length>=limit||stopFlag)break}}rec(0);return out}
function setProgress(){let p=total?Math.min(100,done/total*100):0;$("#bar").style.width=p+"%";$("#pct").textContent=p.toFixed(1)+"%";$("#count").textContent=`${done.toLocaleString()} / ${total.toLocaleString()}`}
function saveHistory(item){let a=JSON.parse(localStorage.getItem("gharhash-history")||"[]");a.unshift(item);localStorage.setItem("gharhash-history",JSON.stringify(a.slice(0,20)));renderHistory()}
function renderHistory(){let a=JSON.parse(localStorage.getItem("gharhash-history")||"[]");$("#history").innerHTML=a.length?a.map(x=>`<div class="historyItem"><b>${esc(x.status)}</b> — ${esc(x.type)}<small>${esc(x.hash.slice(0,18))}… ${x.result?`→ ${esc(x.result)}`:""}</small></div>`).join(""):'<p class="notice">No audits yet.</p>'}
async function run(){if(running)return;let target=$("#hash").value.trim().toLowerCase();if(!/^[0-9a-f]+$/.test(target))return alert("Enter a hexadecimal test hash.");let type=$("#hashType").value;if(type==="auto")type=detect(target)[0];if(!['md5','sha1','sha256','sha512'].includes(type))return alert("Select a supported hash type.");let limit=Math.min(1e6,Math.max(1,+$("#limit").value||1));let words=[];
if($("#mode").value==="dictionary"){let f=$("#wordlist").files[0];if(!f)return alert("Choose a wordlist.");words=(await f.text()).split(/\r?\n/).filter(Boolean).slice(0,limit)}
else words=candidatesFromMask($("#mask").value,limit);
running=true;stopFlag=false;done=0;total=words.length;startTime=performance.now();$("#start").disabled=true;$("#stop").disabled=false;$("#status").textContent="Running";$("#result").textContent="";setProgress();
for(let i=0;i<words.length;i++){if(stopFlag)break;let got=await digest(type,words[i]);done=i+1;setProgress();if(got===target){let sec=((performance.now()-startTime)/1000).toFixed(2);$("#status").textContent="Found";$("#result").textContent=`✓ Match: ${words[i]}  •  ${sec}s`;saveHistory({status:"Found",type,hash:target,result:words[i]});running=false;$("#start").disabled=false;$("#stop").disabled=true;return}if(i%32===0)await new Promise(requestAnimationFrame)}
let status=stopFlag?"Stopped":"Not found";$("#status").textContent=status;$("#result").textContent=status==="Stopped"?"Audit stopped.":"No match in tested candidates.";saveHistory({status,type,hash:target,result:""});running=false;$("#start").disabled=false;$("#stop").disabled=true}
$("#start").onclick=run;$("#stop").onclick=()=>{stopFlag=true};$("#clear").onclick=()=>{localStorage.removeItem("gharhash-history");renderHistory()};renderHistory();