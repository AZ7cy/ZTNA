# Part 10 of ztna.py - docker-compose template, embedded web pages, pooled HTTP server.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

COMPOSE = """services:
  init-data:
    image: python:3.12-slim
    user: "0:0"
    volumes: ["ztna_data:/data", "ztna_anchor:/anchor"]
    command: ["sh", "-c", "mkdir -p /data /anchor && chown -R 65532:65532 /data /anchor"]
  ztna:
    image: python:3.12-slim
    depends_on:
      init-data:
        condition: service_completed_successfully
    working_dir: /app
    volumes: [".:/app:ro", "ztna_data:/data", "ztna_anchor:/anchor", "./certs:/certs:ro"]
    init: true
    command: ["python", "%SCRIPT%", "server"]
    ports: ["127.0.0.1:8443:8443"]
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      ZTNA_HOST: 0.0.0.0
      ZTNA_DEMO: "0"
      ZTNA_DATA_DIR: /data
      ZTNA_ADMIN_KEY: "${ZTNA_ADMIN_KEY:?set a 32+ character ZTNA_ADMIN_KEY}"
      ZTNA_USERS_FILE: /data/users.json
      ZTNA_BOOTSTRAP_USER: "${ZTNA_BOOTSTRAP_USER:?set ZTNA_BOOTSTRAP_USER}"
      ZTNA_BOOTSTRAP_ROLE: "${ZTNA_BOOTSTRAP_ROLE:-admin}"
      ZTNA_BOOTSTRAP_PASSWORD: "${ZTNA_BOOTSTRAP_PASSWORD:?set ZTNA_BOOTSTRAP_PASSWORD}"
      ZTNA_BOOTSTRAP_TOTP: "${ZTNA_BOOTSTRAP_TOTP:?set ZTNA_BOOTSTRAP_TOTP}"
      ZTNA_POSTURE_KEY_LAPTOP_ALICE: "${ZTNA_POSTURE_KEY_LAPTOP_ALICE:?set ZTNA_POSTURE_KEY_LAPTOP_ALICE}"
      ZTNA_POSTURE_KEY_LAPTOP_BOB: "${ZTNA_POSTURE_KEY_LAPTOP_BOB:?set ZTNA_POSTURE_KEY_LAPTOP_BOB}"
      ZTNA_POSTURE_KEY_LAPTOP_CAROL: "${ZTNA_POSTURE_KEY_LAPTOP_CAROL:?set ZTNA_POSTURE_KEY_LAPTOP_CAROL}"
      ZTNA_DEVICE_OWNER_LAPTOP_ALICE: "${ZTNA_DEVICE_OWNER_LAPTOP_ALICE:?set ZTNA_DEVICE_OWNER_LAPTOP_ALICE}"
      ZTNA_DEVICE_OWNER_LAPTOP_BOB: "${ZTNA_DEVICE_OWNER_LAPTOP_BOB:?set ZTNA_DEVICE_OWNER_LAPTOP_BOB}"
      ZTNA_DEVICE_OWNER_LAPTOP_CAROL: "${ZTNA_DEVICE_OWNER_LAPTOP_CAROL:?set ZTNA_DEVICE_OWNER_LAPTOP_CAROL}"
      ZTNA_MANAGED_DEVICES: "${ZTNA_MANAGED_DEVICES:-}"
      ZTNA_OFFICE_CIDRS: "${ZTNA_OFFICE_CIDRS:?set ZTNA_OFFICE_CIDRS}"
      ZTNA_CERT: /certs/server.crt
      ZTNA_KEY: /certs/server.key
      ZTNA_AUDIT_ANCHOR_KEY: "${ZTNA_AUDIT_ANCHOR_KEY:?set ZTNA_AUDIT_ANCHOR_KEY}"
      ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE: /anchor/audit.monotonic
      ZTNA_JWT_KEY: "${ZTNA_JWT_KEY:?set a 64+ character ZTNA_JWT_KEY}"
      ZTNA_SESSION_WRAP_KEY: "${ZTNA_SESSION_WRAP_KEY:?set 32-byte hex session wrap key}"
      ZTNA_ALLOWED_HOSTS: "${ZTNA_ALLOWED_HOSTS:-localhost:8443,127.0.0.1:8443}"
      UP_WIKI: "http://wiki/"
      UP_HR: "http://hr/"
      UP_ADMIN: "http://admin/"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('https://127.0.0.1:8443/baseline', context=__import__('ssl')._create_unverified_context(), timeout=3)"]
      interval: 15s
      timeout: 5s
      retries: 3
    networks: [seg_wiki, seg_hr, seg_admin, edge]
  wiki:  {image: hashicorp/http-echo, command: ["-listen=:80", '-text={\"svc\":\"wiki\"}'], networks: [seg_wiki]}
  hr:    {image: hashicorp/http-echo, command: ["-listen=:80", '-text={\"svc\":\"hr-db\"}'], networks: [seg_hr]}
  admin: {image: hashicorp/http-echo, command: ["-listen=:80", '-text={\"svc\":\"admin\"}'], networks: [seg_admin]}
networks:
  edge: {}
  seg_wiki: {internal: true}
  seg_hr: {internal: true}
  seg_admin: {internal: true}
volumes:
  ztna_data:
  ztna_anchor:
"""

# ---------- GUI (embedded) ----------
INDEX_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZTNA Lab · Manager Console</title>
<style>
:root{--bg:#0d1117;--pn:#151b23;--ln:#262e3a;--tx:#d5dbe3;--mu:#7d8896;--ok:#3ddc97;--no:#ff5c6c;--am:#f2b94b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:14px 22px;border-bottom:1px solid var(--ln)}
h1{font-size:15px;margin:0;letter-spacing:.14em;text-transform:uppercase}h1 b{color:var(--am)}.hk{display:flex;gap:8px;align-items:center}.hk input{width:190px}
.tag{color:var(--mu);font-size:12px}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:14px;padding:14px 22px}
.pn{background:var(--pn);border:1px solid var(--ln);border-radius:6px;padding:14px;min-width:0}.pn h2{margin:0 0 10px;font-size:12px;color:var(--mu);letter-spacing:.12em;text-transform:uppercase}
.wide{grid-column:1/-1}label{display:block;color:var(--mu);font-size:11px;margin:8px 0 3px}
input,select,button{background:#0d1117;color:var(--tx);border:1px solid var(--ln);border-radius:4px;padding:6px 8px;font:inherit;width:100%}
button{cursor:pointer;width:auto;border-color:#3b4656}button:hover{border-color:var(--am)}button.p{background:var(--am);color:#111;border-color:var(--am);font-weight:700}
.row{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.row>*{flex:1}.row>button{flex:0 0 auto}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:4px 6px;border-bottom:1px solid var(--ln);text-align:left;vertical-align:top}th{color:var(--mu);font-weight:400}
.A{color:var(--ok)}.D{color:var(--no)}.R{color:var(--am)}pre{margin:8px 0 0;background:#0d1117;padding:8px;border-radius:4px;overflow:auto;max-height:170px;font-size:12px}
.dev{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:8px;padding-bottom:8px;border-bottom:1px dashed var(--ln)}
.chip{border:1px solid var(--ln);border-radius:3px;padding:1px 7px;font-size:11px;cursor:pointer;user-select:none}.chip.on{color:var(--ok);border-color:var(--ok)}.chip.off{color:var(--no);border-color:var(--no)}
.sc{font-size:20px;font-weight:700;min-width:44px}.big{font-size:26px;font-weight:700}.kpi{display:flex;gap:22px;margin-bottom:10px;flex-wrap:wrap}.kpi small{display:block;color:var(--mu);font-size:11px}
canvas{width:100%;height:110px;display:block}.mt6{margin-top:6px}.w44{width:44%}.bar progress{width:100%;height:8px;vertical-align:middle}.bar{position:relative;background:#0d1117;margin:3px 0;border-radius:3px;overflow:hidden}.bar i{position:absolute;inset:0 auto 0 0;background:#3a2530}.bar span{position:relative;padding:2px 6px;font-size:12px;display:block}
.pol{display:grid;grid-template-columns:90px repeat(4,1fr);gap:6px;align-items:center;margin-bottom:6px}.pol input[type=checkbox]{width:auto}
</style></head><body>
<header><h1>ZTNA <b>Lab</b> · Manager Console</h1><div class="hk"><span class="tag">Authenticated manager</span><button data-action="manager-logout">Log out</button><span class="tag" id="clock"></span></div></header>
<main>
<section class="pn"><h2>1 · Access console (client simulator)</h2>
 <div class="row"><div><label>User</label><select id="u"></select></div><div><label>Device</label><select id="d"></select></div><div><label>Location</label><select id="loc"><option>office</option><option>home</option><option>unknown</option></select></div></div>
 <div class="row"><div><label>Demo bootstrap password</label><input id="pw" type="password"></div><div><label>TOTP code</label><input id="otp" maxlength="6"></div><button data-action="demo-otp">fill OTP</button></div>
 <p class="row"><button class="p" data-action="login">Authenticate</button><button data-action="stepup">Step-up MFA</button><button data-action="logout">Logout</button><span id="who" class="tag"></span></p>
 <div class="row">%%RESOURCE_BUTTONS%%</div>
 <pre id="out">Not authenticated. Default policy: deny.</pre></section>
<section class="pn"><h2>2 · Device posture &amp; clock (admin simulation)</h2><div id="devs"></div>
 <label>Simulated clock hour <span id="hv"></span></label>
 <input type="range" id="hr" min="0" max="23" data-action="set-hour"> <button class="mt6" data-action="real-clock">use real clock</button></section>
<section class="pn"><h2>3 · Active sessions</h2><table id="ses"></table></section>
<section class="pn"><h2>4 · Policy editor (live)</h2><div id="pol"></div><div class="tag">min posture · MFA max age (s) · hours from–to · managed device</div></section>
<section class="pn"><h2>5 · Performance &amp; top deny reasons</h2><div class="kpi" id="kpi"></div><canvas id="cv" width="700" height="110"></canvas><div id="rs"></div></section>
<section class="pn"><h2>6 · Generated segmentation rules (dry run)</h2><pre id="fw"></pre></section>
<section class="pn wide"><h2>7 · Decision log (hash-chained audit trail) <button data-action="verify">verify chain</button> <button data-action="export">export CSV</button> <span id="vr" class="tag"></span></h2><table id="log"></table></section>
</main>
<script>
let tok=null,dev=null,deviceKey=null,pollTimer=null;const $=i=>document.getElementById(i),esc=s=>String(s??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');
const j=async(p,m='GET',b)=>{const h={'Content-Type':'application/json'};if(p.startsWith('/api/')&&!['/api/login','/api/stepup','/api/logout','/api/refresh','/api/demo/totp','/api/ui/manager-login'].includes(p))h['X-Manager-Session']=sessionStorage.getItem('ztnaManagerSession')||'';
 if(tok&&(p.startsWith('/access')||p=='/api/stepup'||p=='/api/logout'||p=='/api/refresh')){h.Authorization='Bearer '+tok;h['X-Device-Id']=dev;if(deviceKey){if(!window.isSecureContext&&!['localhost','127.0.0.1','::1'].includes(location.hostname)){throw new Error('Secure context required for device proof');}const raw=Uint8Array.from(atob(deviceKey.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(deviceKey.length/4)*4,'=')),c=>c.charCodeAt(0));const k=await crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']);const ts=Date.now()/1000;const nonce=crypto.randomUUID();const bodyText=b?JSON.stringify(b):'';const dig=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(bodyText))),x=>x.toString(16).padStart(2,'0')).join('');const u=new URL(p,location.href);const data=new TextEncoder().encode(['ztna-pop-v2',m,u.pathname+u.search,dig,ts.toFixed(3),nonce].join(String.fromCharCode(10)));const sig=new Uint8Array(await crypto.subtle.sign('HMAC',k,data));h['X-Device-Timestamp']=ts.toFixed(3);h['X-Device-Nonce']=nonce;h['X-Content-SHA256']=dig;h['X-Device-Proof']=Array.from(sig,b=>b.toString(16).padStart(2,'0')).join('')}}
 const r=await fetch(p,{method:m,headers:h,body:b?JSON.stringify(b):undefined});return{s:r.status,d:await r.json().catch(()=>({}))}};
async function demoOtp(){$('otp').value=(await j('/api/demo/totp?user='+$('u').value)).d.code||''}
async function login(){if(!window.isSecureContext && !['localhost','127.0.0.1','::1'].includes(location.hostname)){ $('out').textContent='Secure context required: use HTTPS for the ZTNA web console.'; return; }const r=await j('/api/login','POST',{username:$('u').value,password:$('pw').value,otp:$('otp').value,device_id:$('d').value,location:$('loc').value});
 if(r.s==200){tok=r.d.token;dev=$('d').value;deviceKey=r.d.device_key;$('who').textContent='✔ '+$('u').value+' @ '+dev}else{tok=null;deviceKey=null;$('who').textContent='✘ '+(r.d.error||r.s)}$('out').textContent=JSON.stringify(r.d,null,1).slice(0,300);refresh()}
async function acc(x){if(!tok){$('out').textContent='401 – authenticate first';return}const r=await j('/access/'+x);$('out').textContent=r.s+' '+(r.s==200?'ALLOW':r.d.stepup?'STEP-UP (fill OTP, click Step-up MFA)':'DENY')+'\n'+JSON.stringify(r.d,null,1);refresh()}
async function logout(){if(!tok)return;const r=await j('/api/logout','POST',{});tok=null;deviceKey=null;dev=null;$('who').textContent='logged out';$('out').textContent=JSON.stringify(r.d);refresh()}
async function stepup(){if(!tok)return;const r=await j('/api/stepup','POST',{otp:$('otp').value});$('out').textContent=r.s+' '+JSON.stringify(r.d);refresh()}
async function tgl(d,f,v){await j('/api/device/'+d+'/posture','POST',{field:f,value:v});refresh()}
async function setHour(h){await j('/api/sim','POST',{hour:h==null?null:+h});refresh()}
async function rev(s){await j('/api/session/'+s+'/revoke','POST',{});refresh()}
async function pol(r){await j('/api/policy/'+r,'POST',{min_posture:+$('mp_'+r).value,mfa_age:+$('ma_'+r).value,hours:[+$('lo_'+r).value,+$('hi_'+r).value],managed:$('mg_'+r).checked});refresh()}
async function ver(){const r=await j('/api/verify');$('vr').textContent=r.d.ok?'✔ chain intact ('+r.d.entries+' entries)':'✘ TAMPERED at entry '+r.d.broken_at}
async function exp(){const r=await fetch('/api/export',{headers:{'X-Manager-Session':sessionStorage.getItem('ztnaManagerSession')||''}});const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download='ztna_audit.csv';a.click()}
async function managerLogout(){try{await j('/api/ui/manager-logout','POST',{})}catch(e){}sessionStorage.removeItem('ztnaManagerSession');location.href='/ztna'}
async function refresh(){if(!sessionStorage.getItem('ztnaManagerSession')){$('clock').textContent='manager login required';return}const [s,l,m,f]=await Promise.all([j('/api/state'),j('/api/logs'),j('/api/metrics'),j('/api/firewall')]);const st=s.d;
 if(s.s==401){$('clock').textContent='enter admin key';if(pollTimer){clearInterval(pollTimer);pollTimer=null}return}
 if(!pollTimer)pollTimer=setInterval(refresh,2500);
 $('clock').textContent='policy clock '+String(st.hour).padStart(2,'0')+':00'+(st.sim?' (simulated)':'');$('hv').textContent=st.hour;if(document.activeElement!==$('hr'))$('hr').value=st.hour;
 if(!$('u').options.length){$('u').innerHTML=Object.keys(st.users).map(u=>`<option>${esc(u)}</option>`).join('');$('d').innerHTML=Object.keys(st.devices).map(u=>`<option>${esc(u)}</option>`).join('')}
 $('devs').innerHTML=Object.entries(st.devices).map(([n,d])=>`<div class="dev"><span class="sc ${d.score>=70?'A':d.score>=40?'R':'D'}">${d.score}</span><b>${esc(n)}</b>`+['os_updated','disk_encrypted','firewall','antivirus'].map(f=>`<span class="chip ${d[f]?'on':'off'}" data-action="toggle-posture" data-device="${esc(n)}" data-field="${f}" data-value="${!d[f]}">${f}</span>`).join('')+`<span class="chip ${d.corporate_managed?'on':'off'}">corporate_managed (MDM)</span>`+'</div>').join('');
 $('ses').innerHTML='<tr><th>sid<th>user<th>device<th>loc<th>ttl<th>MFA age<th></tr>'+st.sessions.map(x=>`<tr><td>${esc(x.sid)}<td>${esc(x.user)}<td>${esc(x.device)}<td>${esc(x.location)}${x.travel?' ⚠':''}<td>${x.ttl}s<td>${x.mfa}s<td><button data-action="revoke" data-sid="${esc(x.sid)}">revoke</button></tr>`).join('');
 if(!$('pol').contains(document.activeElement))$('pol').innerHTML=Object.entries(st.resources).map(([r,v])=>`<div class="pol"><b>${esc(r)}</b><input id="mp_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.min_posture}"><input id="ma_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.mfa_age}"><span><input id="lo_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.hours[0]}" class="w44">–<input id="hi_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.hours[1]}" class="w44"></span><input id="mg_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="checkbox" ${v.managed?'checked':''}></div>`).join('');
 $('log').innerHTML='<tr><th>time<th>user<th>device<th>resource<th>decision<th>risk<th>reasons / signals</tr>'+l.d.map(e=>`<tr><td>${esc(e.ts.slice(11))}<td>${esc(e.user||'-')}<td>${esc(e.device||'-')}<td>${esc(e.resource)}<td class="${e.decision=='ALLOW'?'A':e.decision=='DENY'?'D':'R'}">${esc(e.decision)}<td>${e.risk??''}<td>${esc(e.reasons.concat(e.signals||[]).join('; '))}</tr>`).join('');
 const k=m.d;$('kpi').innerHTML=`<div><div class="big A">${k.allow}</div><small>allowed</small></div><div><div class="big R">${k.stepup}</div><small>step-ups</small></div><div><div class="big D">${k.deny}</div><small>denied</small></div><div><div class="big">${k.policy_us.p50}µs</div><small>policy eval p50</small></div><div><div class="big">${k.proxy_ms.p95}ms</div><small>request p95</small></div>`;
 const mx2=Math.max(1,...k.reasons.map(r=>r[1]));$('rs').innerHTML=k.reasons.map(([t,n])=>`<div class="bar"><progress max="${mx2}" value="${n}"></progress><span>${esc(t)} · ${n}</span></div>`).join('');
 $('fw').textContent=f.d.rules.join('\n');
 const c=$('cv').getContext('2d');c.clearRect(0,0,700,110);const v=k.series,mx=Math.max(1,...v);c.strokeStyle='#f2b94b';c.beginPath();v.forEach((y,i)=>{const X=i*700/Math.max(1,v.length-1),Y=105-y/mx*92;i?c.lineTo(X,Y):c.moveTo(X,Y)});c.stroke();c.fillStyle='#7d8896';c.fillText('request latency (ms), last '+v.length+' · max '+mx.toFixed(2),6,12)}
document.addEventListener('click',e=>{const b=e.target.closest('[data-action]');if(!b)return;const a=b.dataset.action;if(a==='demo-otp')demoOtp();else if(a==='login')login();else if(a==='stepup')stepup();else if(a==='logout')logout();else if(a==='access')acc(b.dataset.resource);else if(a==='real-clock')setHour(null);else if(a==='manager-logout')managerLogout();else if(a==='verify')ver();else if(a==='export')exp();else if(a==='revoke')rev(b.dataset.sid);else if(a==='toggle-posture')tgl(b.dataset.device,b.dataset.field,b.dataset.value==='true')});
document.addEventListener('change',e=>{const a=e.target.dataset.action;if(a==='policy')pol(e.target.dataset.resource)});
let hourTimer=null;document.addEventListener('input',e=>{if(e.target.dataset.action==='set-hour'){clearTimeout(hourTimer);hourTimer=setTimeout(()=>setHour(e.target.value),250)}});
refresh();
</script></body></html>
"""
INDEX_HTML = INDEX_HTML.replace("%%RESOURCE_BUTTONS%%", "".join(f'<button data-action="access" data-resource="{r}">{r}</button>' for r in RESOURCES))

LANDING_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZTNA Access Portal</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#283653;--text:#edf3ff;--muted:#9aa9c5;--accent:#79a8ff;--green:#55d6a2}*{box-sizing:border-box}body{margin:0;min-height:100vh;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text);background:radial-gradient(circle at 20% 0%,#1b2b50,transparent 40%),var(--bg);display:grid;place-items:center;padding:24px}.wrap{width:min(980px,100%)}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:12px}.title{font-size:clamp(32px,5vw,52px);line-height:1.05;margin:12px 0}.sub{color:var(--muted);max-width:650px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:18px;margin-top:32px}.card{display:flex;flex-direction:column;gap:12px;background:rgba(18,26,44,.94);border:1px solid var(--line);border-radius:22px;padding:26px;box-shadow:0 24px 70px #0003}.icon{width:48px;height:48px;border-radius:14px;display:grid;place-items:center;background:#21345a;color:var(--accent);font-size:24px}.card h2{margin:0;font-size:22px}.card p{margin:0;color:var(--muted);flex:1}.btn{display:inline-flex;justify-content:center;align-items:center;text-decoration:none;background:var(--accent);color:#071126;font-weight:800;border-radius:12px;padding:13px 16px;margin-top:10px}.foot{color:var(--muted);font-size:12px;margin-top:24px}
</style></head><body><main class="wrap"><div class="eyebrow">Zero Trust Network Access</div><h1 class="title">Secure access.<br>Clear decisions.</h1><p class="sub">Choose the workspace that matches your role. Employee access requests are evaluated by the same ZTNA policy engine and appear in the manager console in near real time.</p><div class="cards"><section class="card"><div class="icon">↗</div><h2>Employee access</h2><p>Sign in with your employee account, verify MFA, and request access to approved company resources. See the policy decision and reason.</p><a class="btn" href="/employee">Employee sign in</a></section><section class="card"><div class="icon">▦</div><h2>ZTNA manager</h2><p>Review access requests, active sessions, device posture, policy settings, audit logs, and system health from a dedicated console.</p><a class="btn" href="/ztna">Manager sign in</a></section></div><div class="foot">Demo lab · Requests and logs are shared through the server, so both workspaces can be used from separate laptops on the same network.</div></main></body></html>"""

MANAGER_LOGIN_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZTNA Manager Sign In</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#283653;--text:#edf3ff;--muted:#9aa9c5;--accent:#79a8ff}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(circle at 15% 0%,#1b2b50,transparent 42%),var(--bg);font:16px/1.5 system-ui,sans-serif;color:var(--text)}.card{width:min(440px,100%);padding:30px;background:var(--panel);border:1px solid var(--line);border-radius:22px;box-shadow:0 24px 70px #0004}.eyebrow{font-size:12px;color:var(--accent);letter-spacing:.14em;text-transform:uppercase;font-weight:800}h1{font-size:30px;margin:10px 0 4px}p{color:var(--muted);margin:0 0 24px}label{display:block;font-size:13px;color:var(--muted);margin:15px 0 6px}input,button{width:100%;padding:13px 14px;border-radius:11px;border:1px solid var(--line);font:inherit}input{background:#0b1020;color:var(--text)}button{margin-top:22px;background:var(--accent);color:#071126;font-weight:800;border:0;cursor:pointer}#msg{min-height:24px;color:#ff9aa8;margin-top:14px;font-size:14px}.back{display:inline-block;color:var(--muted);margin-top:12px;text-decoration:none;font-size:14px}
</style></head><body><main class="card"><div class="eyebrow">ZTNA · Operations</div><h1>Manager sign in</h1><p>Authenticate to monitor requests, sessions, policy decisions, and audit records.</p><form id="form"><label for="username">Manager name</label><input id="username" autocomplete="username" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><button type="submit">Sign in to console</button></form><div id="msg" role="status"></div><a class="back" href="/">← Back to workspace selection</a></main><script>
document.getElementById('form').addEventListener('submit',async e=>{e.preventDefault();const msg=document.getElementById('msg');msg.textContent='Signing in…';try{const r=await fetch('/api/ui/manager-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Sign-in failed');sessionStorage.setItem('ztnaManagerSession',d.token);location.href='/ztna/console'}catch(err){msg.textContent=err.message}});
</script></body></html>"""

EMPLOYEE_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Employee · ZTNA Access</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#283653;--text:#edf3ff;--muted:#9aa9c5;--accent:#79a8ff;--good:#55d6a2;--bad:#ff8190;--warn:#ffc86b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0%,#1b2b50,transparent 40%),var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:18px clamp(16px,4vw,48px);border-bottom:1px solid var(--line)}.brand{font-weight:850;letter-spacing:.05em}.brand span{color:var(--accent)}.top a{color:var(--muted);text-decoration:none}.layout{width:min(1080px,100%);margin:auto;padding:clamp(16px,4vw,40px);display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);gap:22px}.panel{background:rgba(18,26,44,.95);border:1px solid var(--line);border-radius:20px;padding:clamp(18px,3vw,28px);min-width:0}.eyebrow{font-size:12px;color:var(--accent);font-weight:800;letter-spacing:.13em;text-transform:uppercase}h1{font-size:clamp(28px,4vw,38px);line-height:1.1;margin:12px 0}h2{font-size:20px;margin:0 0 14px}p{color:var(--muted)}label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}input,select,button{font:inherit;border-radius:10px;padding:12px;border:1px solid var(--line);width:100%}input,select{background:#0b1020;color:var(--text)}button{background:var(--accent);color:#071126;font-weight:800;border:0;cursor:pointer}button.secondary{background:#1a2740;color:var(--text);border:1px solid var(--line)}button:disabled{opacity:.5;cursor:not-allowed}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}.muted{font-size:12px;color:var(--muted)}.status{padding:14px;border:1px solid var(--line);border-radius:12px;background:#0b1020;white-space:pre-wrap;overflow-wrap:anywhere;margin-top:16px}.resources{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}.resource{background:#17233a;color:var(--text);border:1px solid var(--line);padding:15px;text-align:left}.resource strong{display:block}.resource small{display:block;color:var(--muted);font-weight:400;margin-top:4px}.resource:hover{border-color:var(--accent)}.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:4px 10px;font-size:12px;color:var(--muted)}.hidden{display:none!important}.decision{font-weight:850}.allow{color:var(--good)}.deny{color:var(--bad)}.step{color:var(--warn)}@media(max-width:760px){.layout{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.grid2{grid-template-columns:1fr}}
</style></head><body><header class="top"><div class="brand">ZTNA <span>ACCESS</span> · EMPLOYEE</div><a href="/">← Switch workspace</a></header><main class="layout"><section class="panel" id="loginPanel"><div class="eyebrow">Identity verification</div><h1>Welcome back.</h1><p>Sign in to request access. Your identity, device, MFA, and current policy are checked before resources open.</p><form id="loginForm"><label for="user">Employee account</label><select id="user" required></select><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><label for="otp">Authenticator code (TOTP)</label><input id="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="6-digit code" required><label for="device">Device</label><select id="device" required></select><div class="muted" style="margin-top:8px">Use the authenticator code registered for your employee account. For remote devices, use HTTPS.</div><button style="margin-top:20px" type="submit">Sign in securely</button></form><div id="loginMsg" class="status" role="status">Not signed in.</div></section><section class="panel hidden" id="accessPanel"><div class="eyebrow">Employee workspace</div><h1>Request resource access</h1><p id="welcome">Choose a resource below. Each request is checked by the live ZTNA policy engine and recorded in the manager's audit console.</p><div class="grid2"><div><span class="pill" id="userPill">Employee</span></div><div style="text-align:right"><button class="secondary" id="logout" type="button">Sign out</button></div></div><h2 style="margin-top:24px">Available systems</h2><div id="resources" class="resources"></div><div id="result" class="status" aria-live="polite">Choose a system to request access.</div><p class="muted">A denied request is still recorded for security review. A request does not override policy.</p></section></main><script>
const $=id=>document.getElementById(id),esc=s=>String(s??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');let token=null,device=null,deviceKey=null,user=null,catalog=null;
async function req(path,method='GET',body=null,auth=false){const headers={'Content-Type':'application/json'};let raw=body===null?'':JSON.stringify(body);if(auth&&token){headers.Authorization='Bearer '+token;headers['X-Device-Id']=device;const bytes=Uint8Array.from(atob(deviceKey.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(deviceKey.length/4)*4,'=')),c=>c.charCodeAt(0));const key=await crypto.subtle.importKey('raw',bytes,{name:'HMAC',hash:'SHA-256'},false,['sign']);const ts=(Date.now()/1000).toFixed(3),nonce=crypto.randomUUID(),digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw))),x=>x.toString(16).padStart(2,'0')).join('');const u=new URL(path,location.href);const msg=new TextEncoder().encode(['ztna-pop-v2',method,u.pathname+u.search,digest,ts,nonce].join(String.fromCharCode(10)));const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,msg));headers['X-Device-Timestamp']=ts;headers['X-Device-Nonce']=nonce;headers['X-Content-SHA256']=digest;headers['X-Device-Proof']=Array.from(sig,b=>b.toString(16).padStart(2,'0')).join('')};const r=await fetch(path,{method,headers,body:body===null?undefined:raw});return {status:r.status,data:await r.json().catch(()=>({}))}}
async function loadCatalog(){try{const r=await fetch('/api/ui/catalog');catalog=await r.json();if(!r.ok)throw Error(catalog.error||'Demo catalog unavailable');$('user').innerHTML=catalog.users.map(u=>`<option value="${esc(u)}">${esc(u)}</option>`).join('');setDevices();$('user').addEventListener('change',setDevices);$('resources').innerHTML=catalog.resources.map(r=>`<button class="resource" data-resource="${esc(r)}"><strong>${esc(r)}</strong><small>Request access →</small></button>`).join('')}catch(e){$('loginMsg').textContent='Could not load employee directory: '+e.message}}
function setDevices(){const u=$('user').value;const ds=Object.entries(catalog.devices).filter(([name,d])=>d.owner===u).map(([name])=>name);$('device').innerHTML=ds.map(d=>`<option>${esc(d)}</option>`).join('')}
$('loginForm').addEventListener('submit',async e=>{e.preventDefault();$('loginMsg').textContent='Verifying credentials and MFA…';if(!window.isSecureContext&&!['localhost','127.0.0.1','::1'].includes(location.hostname)){$('loginMsg').textContent='Use HTTPS when connecting from another laptop.';return}try{const selectedUser=$('user').value,selectedDevice=$('device').value;const r=await req('/api/login','POST',{username:selectedUser,password:$('password').value,otp:$('otp').value,device_id:selectedDevice});if(r.status!==200)throw Error(r.data.error||'Sign in failed');token=r.data.token;device=selectedDevice;deviceKey=r.data.device_key;user=selectedUser;$('loginPanel').classList.add('hidden');$('accessPanel').classList.remove('hidden');$('userPill').textContent=user+' · '+device;$('welcome').textContent='Signed in as '+user+'. Every request below is evaluated and appears in the manager console.';$('loginMsg').textContent='Signed in';}catch(err){$('loginMsg').textContent=err.message}});
$('resources').addEventListener('click',async e=>{const b=e.target.closest('[data-resource]');if(!b||!token)return;const res=b.dataset.resource;$('result').textContent='Checking '+res+'…';try{const r=await req('/access/'+encodeURIComponent(res),'GET',null,true);const decision=r.status===200?'ALLOW':r.data.stepup?'STEP-UP REQUIRED':'DENY';$('result').innerHTML=`<div class="decision ${decision==='ALLOW'?'allow':decision.startsWith('STEP')?'step':'deny'}">${esc(decision)}</div><div style="margin-top:8px">${esc(res)}</div><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(JSON.stringify(r.data,null,2))}</pre><div class="muted">The request and decision have been sent to the shared audit log.</div>`}catch(err){$('result').textContent='Request failed: '+err.message}});
$('logout').addEventListener('click',async()=>{try{await req('/api/logout','POST',{},true)}catch(e){}token=null;device=null;deviceKey=null;user=null;$('accessPanel').classList.add('hidden');$('loginPanel').classList.remove('hidden');$('password').value='';$('otp').value='';$('loginMsg').textContent='Signed out.'});loadCatalog();
</script></body></html>"""

class PooledHTTPServer(HTTPServer):
    if ":" in HOST_ENV:
        address_family=socket.AF_INET6
    daemon_threads=True
    def handle_error(self, request, client_address):
        # Client disconnects and TLS handshake failures are routine; do not dump
        # tracebacks that can leak request details or flood stderr.
        logger.debug("request handling failed for %s", client_address)
    request_queue_size=128
    def __init__(self,*args,max_workers=32,**kwargs):
        super().__init__(*args,**kwargs)
        self.max_workers=max_workers
        self.slots=threading.BoundedSemaphore(max_workers)
        self.executor=ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix="ztna-http")
    def get_request(self):
        request,client_address=self.socket.accept()
        if getattr(self,"ssl_context",None): request=self.ssl_context.wrap_socket(request,server_side=True,do_handshake_on_connect=False)
        return request,client_address
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            request.close(); return
        try:
            self.executor.submit(self._process_request,request,client_address)
        except Exception:
            self.slots.release(); request.close(); raise
    def _process_request(self,request,client_address):
        try: self.finish_request(request,client_address)
        except Exception: self.handle_error(request,client_address)
        finally:
            self.shutdown_request(request); self.slots.release()
    def server_close(self):
        super().server_close()
        if hasattr(self,"executor"): self.executor.shutdown(wait=True,cancel_futures=True)
