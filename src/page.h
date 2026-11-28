#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
//
// Layout follows AdGuard Home's dashboard: horizontal top nav, a row of stat
// cards with 24 h sparklines, and a two-column panel grid (general statistics,
// top clients, top queried / blocked domains). The markup and CSS are written
// from scratch — AdGuard Home is GPL-3.0 and this project is MIT, so nothing is
// copied from it, and no AdGuard branding is used.
//
// Data comes from /stats.json: seriesQ/seriesB (96 x 15 min buckets covering
// 24 h), topQueried/topBlocked (Misra-Gries heavy hitters) and avgMs.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang=en><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
:root{--bg:#111314;--panel:#1b1e20;--line:#2b3033;--text:#e8ecee;--muted:#8b969c;--orange:#e0823d;--green:#67b279;--blue:#5b8ec9;--grey:#5b6470;--red:#e5534b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:inherit;text-decoration:none}
/* ---- top bar ---- */
.topbar{display:flex;align-items:center;gap:26px;padding:0 22px;height:58px;background:#16191a;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:9}
.brand{display:flex;align-items:center;gap:9px;font-weight:650;font-size:15px;letter-spacing:.3px;white-space:nowrap}
.logo{width:22px;height:22px;color:var(--text)}
.pill{font-size:10px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:3px;background:var(--green);color:#0c1113}
.pill.off{background:var(--orange)}
nav{display:flex;gap:4px;flex:1;min-width:0;overflow:auto}
nav a{display:flex;align-items:center;gap:7px;padding:8px 13px;border-radius:4px;color:var(--muted);font-size:13px;white-space:nowrap;border-bottom:2px solid transparent}
nav a:hover{color:var(--text);background:#1f2426}
nav a.on{color:var(--text);border-bottom-color:var(--orange)}
.ip{color:var(--muted);font-size:12px;white-space:nowrap}
/* ---- page ---- */
.page{padding:20px 22px 70px;max-width:1180px;margin:0 auto}
.head{display:flex;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px}
h1{margin:0;font-size:20px;font-weight:600;letter-spacing:-.2px}
.headacts{display:flex;align-items:center;gap:8px;margin-left:auto;flex-wrap:wrap}
.state{color:var(--muted);font-size:12.5px}
/* ---- stat cards ---- */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
.card{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px 0;min-height:136px;display:flex;flex-direction:column;overflow:hidden}
.card:after{content:"";position:absolute;left:0;right:0;bottom:0;height:2px;background:var(--grey)}
.card.c1:after{background:var(--orange)}.card.c2:after{background:var(--green)}.card.c3:after{background:var(--blue)}
.cv{font-size:25px;font-weight:600;letter-spacing:-.6px;line-height:1.15}
.cl{color:var(--muted);font-size:12.5px;margin-top:3px}
.cd{position:absolute;top:13px;right:14px;font-size:12.5px;font-weight:600;color:var(--orange)}
.spk{margin-top:auto;height:40px}
/* ---- panels ---- */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:6px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-bottom:14px}
.grid .panel{margin-bottom:0}
.phead{padding:12px 16px;border-bottom:1px solid var(--line)}
.phead h2{margin:0;font-size:14.5px;font-weight:600}
.phead .sub{color:var(--muted);font-size:12px}
.kv{list-style:none;margin:0;padding:0}
.kv li{display:flex;justify-content:space-between;gap:14px;padding:10px 16px;border-bottom:1px solid var(--line);font-size:13px}
.kv li:last-child{border-bottom:0}
.kv span{color:var(--muted)}
.kv b{font-weight:600}
/* ---- tables ---- */
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--muted);font-size:12px;font-weight:500;text-align:left;padding:9px 16px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:9px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:#1f2426}
.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.pc{color:var(--muted);font-size:11.5px;margin-left:7px}
.barcell{width:36%}
.bar{height:4px;border-radius:2px;background:var(--orange);min-width:1px}
.dom{word-break:break-all}
.mac{color:var(--muted);font-size:11.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.empty{color:var(--muted);text-align:center;padding:18px}
.tag{font-size:10px;padding:1px 5px;border-radius:3px;background:#3a1f1e;color:#ffb3ae;letter-spacing:.4px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;white-space:nowrap}
.blk{color:var(--orange);font-weight:600}
.alw{color:var(--green)}
/* ---- controls ---- */
.btn{background:#262b2e;color:var(--text);border:1px solid var(--line);border-radius:5px;padding:7px 13px;font:inherit;font-size:13px;cursor:pointer}
.btn:hover{background:#2f353a}
.btn.pri{background:var(--orange);border-color:var(--orange);color:#12100c;font-weight:600}
.btn.pri:hover{background:#ef9251}
.btn.dgr{background:#33191a;border-color:#5a2a2a;color:#ffb3ae}
.btn.sm{padding:3px 9px;font-size:12px}
input,select{background:#141718;border:1px solid var(--line);color:var(--text);border-radius:5px;padding:7px 9px;font:inherit;font-size:13px;max-width:100%}
input:focus,select:focus{outline:none;border-color:var(--orange)}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.sect{padding:14px 16px}
.sect h2{margin:0 0 10px;font-size:14.5px;font-weight:600}
.hint{color:var(--muted);font-size:12px;margin:9px 0 0}
.msg{color:var(--muted);font-size:12px}
#credwarn{display:none;background:#33191a;border:1px solid #5a2a2a;color:#ffb3ae;border-radius:6px;padding:11px 15px;margin-bottom:14px;font-size:13px}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
@media(max-width:620px){
.topbar{height:auto;flex-wrap:wrap;gap:10px;padding:10px 14px}
nav{order:3;flex:1 0 100%;flex-wrap:wrap;overflow:visible}
.page{padding:16px 14px 60px}
.cards{grid-template-columns:1fr 1fr;gap:10px}
.card{min-height:120px;padding:12px 13px 0}
.cv{font-size:21px}
th,td{padding:8px 10px;font-size:12px}
.barcell{width:28%}
}
</style></head><body>
<header class=topbar>
<div class=brand><svg class=logo viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5.2v6.3c0 5 3.4 9.3 8 10.5 4.6-1.2 8-5.5 8-10.5V5.2L12 2z" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>C3 AdBlock<span class=pill id=blockdot>ON</span></div>
<nav>
<a href="#/dashboard" class=on>Dashboard</a>
<a href="#/log">Query Log</a>
<a href="#/filters">Filters</a>
<a href="#/firmware">Firmware</a>
<a href="#/settings">Settings</a>
</nav>
<span class=ip id=host></span>
</header>
<main class=page id=top>
<div class=pg data-page=dashboard>
<div class=head>
<h1>Dashboard</h1>
<div class=headacts id=blockbar>
<span class=state id=blockstate>Blocking active</span>
<select id=pausedur><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I re-enable</option></select>
<button class="btn pri" id=pausebtn onclick=togglePause()>Disable protection</button>
<button class=btn onclick=load()>Refresh statistics</button>
</div>
</div>
<div id=credwarn>&#9888;&#65039; <b>Default credentials in use.</b> WEB_PASS/OTA_PASS in <code>secrets.h</code> are still the placeholder values &mdash; anyone can read them in the public repo. Set real values and reflash.</div>
<div class=cards id=sys></div>

<div class=grid>
<section class=panel>
<div class=phead><h2>General statistics</h2><div class=sub>for the last 24 hours</div></div>
<ul class=kv>
<li><span>DNS queries</span><b id=gq>&mdash;</b></li>
<li><span>Blocked by filters</span><b id=gb>&mdash;</b></li>
<li><span>Allowed</span><b id=ga>&mdash;</b></li>
<li><span>Blocked ratio</span><b id=gp>&mdash;</b></li>
<li><span>Average processing time</span><b id=gavg>&mdash;</b></li>
<li><span>Uptime</span><b id=gup>&mdash;</b></li>
<li><span>Free RAM</span><b id=gram>&mdash;</b></li>
<li><span>Temperature</span><b id=gtemp>&mdash;</b></li>
<li><span>WiFi signal</span><b id=grssi>&mdash;</b></li>
</ul>
</section>

<section class=panel id=clients>
<div class=phead><h2>Top clients</h2><div class=sub>by request count</div></div>
<div class=tw><table id=ct><thead><tr><th>Client</th><th class=num>Requests</th><th class=barcell></th><th></th></tr></thead><tbody></tbody></table></div>
</section>

<section class=panel>
<div class=phead><h2>Top queried domains</h2><div class=sub>most requested</div></div>
<div class=tw><table id=tqt><thead><tr><th>Domain</th><th class=num>Requests</th><th class=barcell></th></tr></thead><tbody></tbody></table></div>
</section>

<section class=panel>
<div class=phead><h2>Top blocked domains</h2><div class=sub>most blocked</div></div>
<div class=tw><table id=tbt><thead><tr><th>Domain</th><th class=num>Requests</th><th class=barcell></th></tr></thead><tbody></tbody></table></div>
</section>
</div>
</div>

<div class=pg data-page=log style=display:none>
<div class=head><h1>Query Log</h1></div>
<section class=panel id=log>
<div class=phead><h2>Query log <span class=sub>&middot; RAM only, cleared on reboot</span></h2></div>
<div class=sect>
<div class=row>
<button class="btn pri" id=logbtn onclick=toggleLog()>Enable logging</button>
<button class=btn onclick=loadLog()>Refresh</button>
<span class=msg id=lognote></span>
</div>
<p class=hint id=logwarn>Off by default. A query log records every domain every device on this network visits, and this dashboard is served over plain HTTP &mdash; anyone able to sniff the LAN could read it. Nothing is written to flash, and disabling discards what was captured.</p>
</div>
<div class=tw><table id=lt><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Result</th></tr></thead><tbody></tbody></table></div>
</section>
</div>

<div class=pg data-page=filters style=display:none>
<div class=head><h1>Filters</h1></div>
<section class=panel id=custom>
<div class=sect>
<h2>Custom blocked domains</h2>
<div class=row><input id=dom placeholder="ads.example.com" size=30><button class="btn pri" onclick=addDom()>Block domain</button></div>
</div>
<div class=tw><table id=cl><tbody></tbody></table></div>
</section>

<section class=panel id=blk>
<div class=sect>
<h2>Blocklist &mdash; upload</h2>
<form id=upf class=row><input type=file id=blf accept=.bin><button class="btn pri">Upload blocklist</button><span id=upmsg class=msg></span></form>
<p class=hint>Build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB needed.</p>
</div>
</section>

<section class=panel id=upd>
<div class=sect>
<h2>Blocklist &mdash; remote auto-update</h2>
<div class=row><input id=uurl placeholder="https://host/blocklist.bin" size=40> every <input id=uiv size=2 value=24>h
<button class="btn pri" onclick=saveUpd()>Save</button><button class=btn onclick=fetchNow()>Fetch now</button></div>
<p class=hint>Device pulls a prebuilt <code>blocklist.bin</code> on a schedule (e.g. a GitHub release asset). Last: <span id=ustat>&mdash;</span></p>
</div>
</section>
</div>

<div class=pg data-page=firmware style=display:none>
<div class=head><h1>Firmware</h1></div>
<section class=panel id=fw>
<div class=sect>
<h2>Firmware &mdash; OTA update</h2>
<form id=fwf class=row><input type=file id=fwb accept=.bin><button class="btn pri">Flash firmware</button><span id=fwmsg class=msg></span></form>
<p class=hint>Upload <code>.pio/build/&lt;env&gt;/firmware.bin</code> (<code>c3</code>, <code>esp32dev</code>, ...) &mdash; the device verifies it and reboots into it.</p>
</div>
</section>
</div>

<div class=pg data-page=settings style=display:none>
<div class=head><h1>Settings</h1></div>
<section class=panel id=dns>
<div class=sect>
<h2>Upstream DNS &mdash; forwarder</h2>
<div class=row><input id=dnsip placeholder="9.9.9.9" size=18>
<button class="btn pri" onclick=saveDns()>Save</button>
<button class=btn onclick="presetDns('1.1.1.1')">Cloudflare</button>
<button class=btn onclick="presetDns('94.140.14.14')">AdGuard</button>
<button class=btn onclick="dnsMode('router')">Use router's DNS</button>
<button class=btn onclick="dnsMode('reset')">Default (Quad9)</button></div>
<p class=hint>Where allowed lookups are forwarded. Keep the default if this box is the <i>backup</i> for a Pi-hole/AdGuard your router hands out &mdash; forwarding there fails exactly when the backup is needed. <span id=dnsmsg></span></p>
</div>
</section>

<section class=panel id=wifi>
<div class=sect>
<h2>WiFi</h2>
<div class=row><button class="btn dgr" onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()">Forget WiFi</button></div>
</div>
</section>
</div>
</main>
<script>
function fmt(n){return (n||0).toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
const tqtEl=document.getElementById('tqt'),tbtEl=document.getElementById('tbt');
let logOnState=false;
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
// 24 h sparkline. Fixed 100x40 viewBox + preserveAspectRatio:none so it scales
// with the card without measuring the DOM.
function spark(el,data,color){
  const h=40,n=data.length;if(!n)return;
  const mx=Math.max(1,...data);
  const pts=data.map((v,i)=>`${(i*100/(n-1||1)).toFixed(2)},${(h-1-(v/mx)*(h-2)).toFixed(2)}`).join(' ');
  el.innerHTML=`<svg viewBox="0 0 100 ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px;display:block"><polygon points="0,${h} ${pts} 100,${h}" fill="${color}" opacity=".22"/><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.2" vector-effect="non-scaling-stroke"/></svg>`;
}
function bars(rows,cols){
  rows=(rows||[]).slice(0,8);
  if(!rows.length)return `<tr><td colspan=${cols} class=empty>No data yet</td></tr>`;
  const mx=Math.max(1,...rows.map(r=>r.n));
  return rows.map(r=>`<tr><td class=dom>${esc(r.d)}</td><td class=num>${fmt(r.n)}<span class=pc>${(100*r.n/mx).toFixed(2)}%</span></td><td class=barcell><div class=bar style="width:${(100*r.n/mx).toFixed(1)}%"></div></td></tr>`).join('');
}
// Query log. /log.json is credential-protected (unlike /stats.json) because it is
// a browsing history for the whole LAN, so a 401 here just lets the browser prompt
// and retry; there is nothing useful to render until it succeeds.
async function loadLog(){
  try{
    const r=await fetch('/log.json',{cache:'no-store'});
    if(!r.ok)return;
    const s=await r.json();
    logOnState=!!s.on;
    logbtn.textContent=s.on?'Disable logging':'Enable logging';
    logbtn.className='btn '+(s.on?'dgr':'pri');
    logwarn.style.display=s.on?'none':'block';
    lognote.textContent=s.on
      ?(s.total+' entries · newest first · '+(s.clock?'clock synced':'waiting for clock'))
      :'logging off';
    const e=s.entries||[];
    lt.tBodies[0].innerHTML=e.length?e.map(x=>{
      const t=x.t?new Date(x.t*1000).toLocaleTimeString():'—';
      return '<tr><td class=mono>'+t+'</td><td>'+x.ip+'</td><td class=dom>'+esc(x.d)+'</td><td class="'+(x.b?'blk':'alw')+'">'+(x.x?'BANNED':(x.b?'BLOCKED':'allowed'))+'</td></tr>';
    }).join(''):'<tr><td colspan=4 class=empty>'+(s.on?'Nothing captured yet':'Logging is disabled')+'</td></tr>';
  }catch(_){}
}
async function toggleLog(){
  const r=await fetch('/setlog?on='+(logOnState?'0':'1'),{headers:CSRF_HDRS});
  if(!r.ok){alert('✗ '+await r.text());return;}
  loadLog();
}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent=s.ip;
credwarn.style.display=s.defcreds?'block':'none';
logOnState=s.logOn===true;
logbtn.textContent=logOnState?'Disable logging':'Enable logging';
logbtn.className='btn '+(logOnState?'dgr':'pri');
logwarn.style.display=logOnState?'none':'block';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'ON':'PAUSED';blockdot.className='pill'+(on?'':' off');
blockstate.textContent=on?'Blocking active':(s.resumeIn>0?'Paused — resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Disable protection':'Enable protection';
pausedur.style.display=on?'':'none';
const Q=s.seriesQ||[],B=s.seriesB||[];
const A=Q.map((v,i)=>Math.max(0,v-(B[i]||0)));
const tot=(s.blocked||0)+(s.allowed||0);
const pb=tot?(100*(s.blocked||0)/tot).toFixed(1):'0.0';
const pa=tot?(100*(s.allowed||0)/tot).toFixed(1):'0.0';
const cards=[
 {k:'',v:fmt(tot),l:'DNS Queries',d:'',data:Q,c:'#5b6470'},
 {k:'c1',v:fmt(s.blocked),l:'Blocked by Filters',d:pb+'%',data:B,c:'#e0823d'},
 {k:'c2',v:fmt(s.allowed),l:'Allowed',d:pa+'%',data:A,c:'#67b279'},
 {k:'c3',v:fmt(s.domains),l:'Blocklist entries',d:'',data:null,c:'#5b8ec9'}];
sys.innerHTML=cards.map(c=>`<div class="card ${c.k}"><div class=cv>${c.v}</div><div class=cl>${c.l}</div>${c.d?'<div class=cd>'+c.d+'</div>':''}<div class=spk></div></div>`).join('');
const spks=sys.querySelectorAll('.spk');
cards.forEach((c,i)=>{if(c.data&&c.data.length)spark(spks[i],c.data,c.c);});
gq.textContent=fmt(tot);gb.textContent=fmt(s.blocked);ga.textContent=fmt(s.allowed);
gp.textContent=pb+'%';gavg.textContent=(s.avgMs||0)+' ms';
gup.textContent=s.uptime;gram.textContent=Math.round((s.heap||0)/1024)+' KB';
gtemp.textContent=s.temp+' °C';grssi.textContent=s.rssi+' dBm';
const cl=s.clients.slice().sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).slice(0,8);
const cmax=Math.max(1,...cl.map(c=>c.blocked+c.allowed));
ct.tBodies[0].innerHTML=cl.length?cl.map(c=>{const t=c.blocked+c.allowed;const w=(100*t/cmax).toFixed(1);
 return `<tr><td>${c.ip}${c.banned?' <span class=tag>BANNED</span>':''}<div class=mac>${c.mac}</div></td><td class=num>${fmt(t)}<span class=pc>${w}%</span></td><td class=barcell><div class=bar style="width:${w}%"></div></td><td><button class="btn sm ban" data-ip="${c.ip}">${c.banned?'Unban':'Ban'}</button></td></tr>`;}).join('')
 :`<tr><td colspan=4 class=empty>No clients yet</td></tr>`;
tqtEl.tBodies[0].innerHTML=bars(s.topQueried||[],3);
tbtEl.tBodies[0].innerHTML=bars(s.topBlocked||[],3);
cl_tBody(s);
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
if(document.activeElement!=dnsip)dnsip.value=s.dns||'';
dnsmsg.textContent=s.dnsSource||'';
ustat.textContent=s.upstat||'—';}
function cl_tBody(s){document.getElementById('cl').tBodies[0].innerHTML=(s.custom||[]).map(d=>`<tr><td class=dom>${esc(d)}</td><td class=num><button class="btn sm rmbtn" data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td colspan=2 class=empty>none yet</td></tr>';}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
document.getElementById('cl').addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
function saveDns(){let v=dnsip.value.trim();if(!v)return;fetch('/setdns?ip='+encodeURIComponent(v),{headers:CSRF_HDRS}).then(async r=>{if(!r.ok)alert('✗ '+await r.text());load()})}
function presetDns(ip){dnsip.value=ip;saveDns()}
function dnsMode(m){fetch('/setdns?'+m+'=1',{headers:CSRF_HDRS}).then(load)}
// Hash router: exactly one page is visible at a time. Kept client-side so the
// firmware still serves a single document and needs no extra routes; #/log and
// friends stay bookmarkable and back/forward work. All pages stay in the DOM, so
// the existing code below can keep touching their elements without guards.
const _nav=[...document.querySelectorAll('nav a')];
const _pages=['dashboard','log','filters','firmware','settings'];
function route(){
  let h=(location.hash||'').replace(/^#\/?/,'')||'dashboard';
  if(_pages.indexOf(h)<0)h='dashboard';
  _pages.forEach(p=>{const el=document.querySelector('[data-page="'+p+'"]');if(el)el.style.display=(p===h)?'':'none';});
  _nav.forEach(a=>a.classList.toggle('on',a.getAttribute('href')==='#/'+h));
  if(h==='dashboard')load();
  if(h==='log')loadLog();
  window.scrollTo(0,0);
}
addEventListener('hashchange',route);
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='flashing '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ rebooting, reconnect in ~15s':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ rebooting, reconnect in ~15s';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
route();setInterval(load,3000);
</script></body></html>)HTML";
