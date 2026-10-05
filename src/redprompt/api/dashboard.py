"""Single-page security dashboard served at ``/`` by the API."""

from __future__ import annotations

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RedPrompt Dashboard</title>
<style>
  :root{--bg:#0f1419;--panel:#1a2029;--ink:#e6edf3;--muted:#8b949e;--line:#2d333b;--accent:#58a6ff;
    --critical:#e5484d;--high:#f0883e;--medium:#e3b341;--low:#3fb950;--info:#6e7681;--vuln:#e5484d;--tested:#3fb950;--untested:#8b949e;}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  header{background:var(--panel);border-bottom:1px solid var(--line);padding:14px 22px;display:flex;align-items:center;gap:16px}
  header h1{font-size:18px;margin:0}header .v{color:var(--muted);font-size:12px}
  header .warn{margin-left:auto;color:var(--medium);font-size:12px}
  nav{display:flex;gap:4px;padding:8px 22px;background:var(--panel);border-bottom:1px solid var(--line);flex-wrap:wrap}
  nav button{background:transparent;border:1px solid transparent;color:var(--muted);padding:6px 14px;border-radius:8px;cursor:pointer;font-size:14px}
  nav button.active{background:var(--bg);color:var(--ink);border-color:var(--line)}
  main{max-width:1080px;margin:0 auto;padding:22px}
  .grid{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:110px;flex:1;text-align:center}
  .stat .n{font-size:28px;font-weight:700}.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase}
  table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);text-transform:uppercase;font-size:11px}
  .badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;color:#0b0f14}
  .b-critical{background:var(--critical);color:#fff}.b-high{background:var(--high)}.b-medium{background:var(--medium)}.b-low{background:var(--low)}.b-info{background:var(--info);color:#fff}
  .hidden{display:none}.muted{color:var(--muted)}
  .surface{display:flex;gap:40px;padding:16px 0;align-items:flex-start;overflow-x:auto}
  .col{display:flex;flex-direction:column;gap:14px}
  .node{background:var(--panel);border:2px solid var(--line);border-radius:10px;padding:10px 14px;min-width:140px;text-align:center}
  .node small{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;margin-top:2px}
  .s-vulnerable{border-color:var(--vuln)}.s-tested{border-color:var(--tested)}.s-untested{border-color:var(--untested);opacity:.7}.s-discovered{border-color:var(--accent)}
  select,input{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:6px 8px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:12px}
</style>
</head>
<body>
<header>
  <h1>RedPrompt</h1><span class="v" id="ver"></span>
  <span class="warn" id="authwarn"></span>
</header>
<nav id="nav">
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="targets">Targets</button>
  <button data-tab="findings">Findings</button>
  <button data-tab="tests">Test Library</button>
  <button data-tab="surface">Attack Surface</button>
</nav>
<main>
  <section id="overview"></section>
  <section id="targets" class="hidden"></section>
  <section id="findings" class="hidden"></section>
  <section id="tests" class="hidden"></section>
  <section id="surface" class="hidden"></section>
</main>
<script>
const TOKEN = localStorage.getItem('rp_token') || '';
async function api(path){
  const h = TOKEN ? {'Authorization':'Bearer '+TOKEN} : {};
  const r = await fetch('/api'+path,{headers:h});
  if(r.status===401){ const t=prompt('API token:'); if(t){localStorage.setItem('rp_token',t);location.reload();} throw new Error('unauthorized'); }
  return r.json();
}
const sev = s => `<span class="badge b-${s}">${s}</span>`;
function show(tab){
  document.querySelectorAll('main section').forEach(s=>s.classList.add('hidden'));
  document.getElementById(tab).classList.remove('hidden');
  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
  render(tab);
}
document.querySelectorAll('#nav button').forEach(b=>b.onclick=()=>show(b.dataset.tab));

async function render(tab){
  if(tab==='overview'){
    const h=await api('/health');
    document.getElementById('ver').textContent='v'+h.version;
    document.getElementById('authwarn').textContent = h.auth_required ? '' : '⚠ API is open (no token set)';
    const f=await api('/findings');
    const c={critical:0,high:0,medium:0,low:0,info:0}; f.forEach(x=>c[x.severity]++);
    document.getElementById('overview').innerHTML=`
      <div class="grid">
        <div class="stat"><div class="n">${h.targets}</div><div class="l">Targets</div></div>
        <div class="stat"><div class="n">${h.scans}</div><div class="l">Scans</div></div>
        <div class="stat"><div class="n">${h.tests}</div><div class="l">Tests</div></div>
        <div class="stat"><div class="n">${h.findings}</div><div class="l">Findings</div></div>
        <div class="stat"><div class="n" style="color:var(--critical)">${c.critical}</div><div class="l">Critical</div></div>
        <div class="stat"><div class="n" style="color:var(--high)">${c.high}</div><div class="l">High</div></div>
        <div class="stat"><div class="n" style="color:var(--medium)">${c.medium}</div><div class="l">Medium</div></div>
      </div>
      <div class="card"><b>Top findings</b><table><thead><tr><th>ID</th><th>Sev</th><th>Risk</th><th>Title</th></tr></thead><tbody>
      ${f.slice(0,8).map(x=>`<tr><td>${x.finding_id}</td><td>${sev(x.severity)}</td><td>${x.risk_score}</td><td>${x.title}</td></tr>`).join('')}
      </tbody></table></div>`;
  }
  if(tab==='targets'){
    const t=await api('/targets');
    document.getElementById('targets').innerHTML=`<table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Provider</th><th>URL</th><th>Authorized</th></tr></thead><tbody>
      ${t.map(x=>`<tr><td>${x.id}</td><td>${x.name}</td><td>${x.app_type}</td><td>${x.llm_provider||'-'}</td><td class="muted">${x.base_url}</td><td>${x.authorized?'✓':'✗'}</td></tr>`).join('')||'<tr><td colspan=6 class="muted">No targets</td></tr>'}</tbody></table>`;
  }
  if(tab==='findings'){
    const f=await api('/findings');
    document.getElementById('findings').innerHTML=`<table><thead><tr><th>ID</th><th>Sev</th><th>Risk</th><th>Conf</th><th>Status</th><th>Title</th></tr></thead><tbody>
      ${f.map(x=>`<tr><td>${x.finding_id}</td><td>${sev(x.severity)}</td><td>${x.risk_score}</td><td>${Math.round(x.confidence*100)}%</td><td>${x.status}</td><td>${x.title}</td></tr>`).join('')||'<tr><td colspan=6 class="muted">No findings</td></tr>'}</tbody></table>`;
  }
  if(tab==='tests'){
    const t=await api('/tests');
    document.getElementById('tests').innerHTML=`<table><thead><tr><th>ID</th><th>Category</th><th>Severity</th><th>Name</th><th>Flags</th></tr></thead><tbody>
      ${t.map(x=>`<tr><td>${x.test_id}</td><td>${x.category}</td><td>${sev(x.default_severity)}</td><td>${x.name}</td><td class="muted">${[x.heuristic?'heuristic':'',x.experimental?'experimental':''].filter(Boolean).join(', ')}</td></tr>`).join('')}</tbody></table>
      <p class="muted">${t.length} tests</p>`;
  }
  if(tab==='surface'){
    const targets=await api('/targets');
    const sel=`<select id="stgt">${targets.map(t=>`<option value="${t.id}">${t.name}</option>`).join('')}</select>`;
    document.getElementById('surface').innerHTML=`<div class="card">Target: ${sel}</div><div id="graph"></div>`;
    const draw=async()=>{
      const id=document.getElementById('stgt').value;
      if(!id){document.getElementById('graph').innerHTML='<p class="muted">No target</p>';return;}
      const g=await api('/targets/'+id+'/attack-surface');
      // group nodes by simple depth from edges
      const depth={}; g.nodes.forEach(n=>depth[n.id]=0);
      for(let i=0;i<4;i++) g.edges.forEach(e=>{depth[e.to]=Math.max(depth[e.to],(depth[e.from]||0)+1)});
      const cols={}; g.nodes.forEach(n=>{(cols[depth[n.id]]=cols[depth[n.id]]||[]).push(n)});
      document.getElementById('graph').innerHTML='<div class="surface">'+Object.keys(cols).sort().map(d=>
        '<div class="col">'+cols[d].map(n=>`<div class="node s-${n.status}"><b>${n.label}</b><small>${n.status}</small></div>`).join('')+'</div>'
      ).join('')+'</div><p class="muted">Border colour: red=vulnerable, green=tested, grey=untested, blue=structural.</p>';
    };
    document.getElementById('stgt').onchange=draw; draw();
  }
}
show('overview');
</script>
</body>
</html>"""
