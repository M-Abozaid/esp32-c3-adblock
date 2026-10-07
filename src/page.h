#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
// UI text lives in the I18N dict below (zh/en); the language <select> in the
// header switches it and localStorage remembers the choice.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px;display:inline-block}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
#langsel{float:right;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:4px 6px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><select id=langsel onchange="LANG=this.value;localStorage.setItem('lang',LANG);applyLang()"><option value=zh>中文</option><option value=en>English</option></select>
<h1>🛡️ C3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
<span data-i18n-html=credwarn></span>
</div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1></b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30 data-i18n=dur30></option><option value=300 selected data-i18n=dur300></option><option value=1800 data-i18n=dur1800></option><option value=0 data-i18n=dur0></option></select>
<button id=pausebtn onclick=togglePause()></button></div>
<div class=cards id=sys></div>
<h2 data-i18n=hClients></h2><table id=ct><thead><tr><th data-i18n=thClient></th><th>MAC</th><th data-i18n=thBlocked></th><th data-i18n=thAllowed></th><th></th></tr></thead><tbody></tbody></table>
<h2 data-i18n=hCustom></h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom() data-i18n=blockDomain></button></div>
<table id=cl><tbody></tbody></table>
<h2 data-i18n=hUpload></h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button data-i18n=uploadBl></button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px" data-i18n=uploadHint></div>
<h2 data-i18n=hRemote></h2>
<div style=margin-bottom:6px><span data-i18n=everyLbl></span> <input id=uurl placeholder="https://host/blocklist.bin" size=40> <span data-i18n=everyLbl2></span> <input id=uiv size=2 value=24><span data-i18n=hrLbl></span>
<button onclick=saveUpd() data-i18n=save></button> <button onclick=fetchNow() data-i18n=fetchNow></button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px"><span data-i18n=remoteHint></span><span id=ustat>&mdash;</span></div>
<h2 data-i18n=hFw></h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button data-i18n=flashFw></button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px" data-i18n=fwHint></div>
<h2>WiFi</h2>
<div style="margin-bottom:18px"><button id=forgetbtn></button></div>
</div><script>
const I18N={
zh:{blockActive:'拦截运行中',paused:'已暂停',pausedIn:s=>'已暂停 — '+s+' 秒后恢复',pause:'暂停',resume:'恢复',
dur30:'30 秒',dur300:'5 分钟',dur1800:'30 分钟',dur0:'直到手动恢复',
hClients:'客户端',thClient:'客户端',thBlocked:'已拦截',thAllowed:'已放行',
hCustom:'自定义拦截域名',blockDomain:'添加拦截',
hUpload:'拦截列表 — 上传',uploadBl:'上传拦截列表',
uploadHint:'用 tools/build_blocklist.py 生成 blocklist.bin 后在此上传——无需 USB',
hRemote:'拦截列表 — 自动更新',everyLbl:'每',everyLbl2:'隔',hrLbl:' 小时',save:'保存',fetchNow:'立即拉取',
remoteHint:'设备按周期拉取预构建的 blocklist.bin（例如 GitHub release 附件）。上次：',
hFw:'固件 — OTA 在线更新',flashFw:'刷入固件',
fwHint:'上传 .pio/build/c3/firmware.bin——设备校验后自动重启进入新固件',
forget:'忘记 WiFi',forgetConfirm:'忘记已保存的 WiFi 并重启进入配网模式？',
cBlocked:'累计拦截',cAllowed:'累计放行',cBlocklist:'拦截列表',cDomains:n=>fmt(n)+' 个域名',
cClients:'客户端',cWifi:'WiFi 信号',cTemp:'温度',cRam:'可用内存',cUptime:'运行时长',
bannedTag:'已拉黑',ban:'拉黑',unban:'解除',remove:'删除',noneYet:'暂无',
fetching:'拉取中…',flashing:m=>'刷入中 '+m+' MB…',uploading:m=>'上传中 '+m+' MB…',
fwOk:'✓ 正在重启，约 15 秒后重连',blOk:'✓ 已更新',uploadFail:'✗ 上传失败',
credwarn:'⚠️ <b>仍在使用默认凭据。</b><code>secrets.h</code> 里的 WEB_PASS/OTA_PASS 仍是占位符——公开仓库里谁都能查到，请改成真实值后重新烧录。',
never:'从未',noUrl:'未设置 URL',beginFail:'初始化失败',fsFail:'文件系统写入失败',
okDomains:n=>'成功：'+fmt(n)+' 个域名',badData:b=>'数据无效（'+b+'B）'},
en:{blockActive:'Blocking active',paused:'Paused',pausedIn:s=>'Paused — resumes in '+s+'s',pause:'Pause',resume:'Resume',
dur30:'30s',dur300:'5 min',dur1800:'30 min',dur0:'until I re-enable',
hClients:'CLIENTS',thClient:'Client',thBlocked:'Blocked',thAllowed:'Allowed',
hCustom:'CUSTOM BLOCKED DOMAINS',blockDomain:'Block domain',
hUpload:'BLOCKLIST — UPLOAD',uploadBl:'Upload blocklist',
uploadHint:'build blocklist.bin with tools/build_blocklist.py, then upload here — no USB',
hRemote:'BLOCKLIST — REMOTE AUTO-UPDATE',everyLbl:'pull',everyLbl2:'',hrLbl:'h',save:'Save',fetchNow:'Fetch now',
remoteHint:'device pulls a prebuilt blocklist.bin on a schedule (e.g. a GitHub release asset). last: ',
hFw:'FIRMWARE — OTA UPDATE',flashFw:'Flash firmware',
fwHint:'upload .pio/build/c3/firmware.bin — device verifies it and reboots into it',
forget:'Forget WiFi',forgetConfirm:'Forget saved WiFi and reboot into the setup portal?',
cBlocked:'Total blocked',cAllowed:'Total allowed',cBlocklist:'Blocklist',cDomains:n=>fmt(n)+' domains',
cClients:'Clients',cWifi:'WiFi',cTemp:'Temp',cRam:'Free RAM',cUptime:'Uptime',
bannedTag:'BANNED',ban:'Ban',unban:'Unban',remove:'remove',noneYet:'none yet',
fetching:'fetching...',flashing:m=>'flashing '+m+' MB...',uploading:m=>'uploading '+m+' MB...',
fwOk:'✓ rebooting, reconnect in ~15s',blOk:'✓ updated',uploadFail:'✗ upload failed',
credwarn:'⚠️ <b>Default credentials in use.</b> WEB_PASS/OTA_PASS in <code>secrets.h</code> are still the placeholder values — anyone can read them in the public repo. Set real values and reflash.',
never:'never',noUrl:'no url set',beginFail:'begin failed',fsFail:'fs open failed',
okDomains:n=>'ok: '+fmt(n)+' domains',badData:b=>'bad data ('+b+'B)'}};
let LANG=localStorage.getItem('lang')||((navigator.language||'en').startsWith('zh')?'zh':'en'),T=I18N[LANG];
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function lstat(s){if(!s||s=='—')return'—';if(s=='never')return T.never;if(s=='no url set')return T.noUrl;
if(s=='begin failed')return T.beginFail;if(s=='fs open failed')return T.fsFail;
let m=String(s).match(/^ok: ([\d,]+) domains$/);if(m)return T.okDomains(Number(m[1].replace(/,/g,'')));
m=String(s).match(/^bad data \((\d+)B\)$/);if(m)return T.badData(+m[1]);return s}
function applyLang(){T=I18N[LANG];langsel.value=LANG;
document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=T[el.dataset.i18n]});
document.querySelectorAll('[data-i18n-html]').forEach(el=>{el.innerHTML=T[el.dataset.i18nHtml]});
forgetbtn.textContent=T.forget;forgetbtn.onclick=()=>{if(confirm(T.forgetConfirm))forgetWifi()};load()}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?T.blockActive:(s.resumeIn>0?T.pausedIn(s.resumeIn):T.paused);
pausebtn.textContent=on?T.pause:T.resume;pausedur.style.display=on?'':'none';
sys.innerHTML=[[T.cBlocked,fmt(s.blocked),'b'],[T.cAllowed,fmt(s.allowed),'a'],[T.cBlocklist,T.cDomains(s.domains),''],
[T.cClients,s.clients.length,''],[T.cWifi,s.rssi+' dBm',''],[T.cTemp,s.temp+' °C',''],[T.cRam,Math.round(s.heap/1024)+' KB',''],[T.cUptime,s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?` <span class=tag style=color:#f85149>${T.bannedTag}</span>`:''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${c.ip}">${c.banned?T.unban:T.ban}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">${T.remove}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${T.noneYet}</td></tr>`;
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=lstat(s.upstat);}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent=T.fetching;fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent=T.flashing((f.size/1048576).toFixed(2));
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?T.fwOk:'✗ '+await r.text();}
catch(_){fwmsg.textContent=T.fwOk;}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent=T.uploading((f.size/1048576).toFixed(2));
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?T.blOk:'✗ '+await r.text();}
catch(_){upmsg.textContent=T.uploadFail;}
blf.value='';setTimeout(load,600);};
applyLang();setInterval(load,3000);
</script></body></html>)HTML";
