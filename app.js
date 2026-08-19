const SEV_COLOR = {Critical:"var(--sev-critical)",High:"var(--sev-high)",Medium:"var(--sev-medium)",Low:"var(--sev-low)",Info:"var(--sev-info)"};
const DEMO_DOTS = {"safe-cafe":"var(--safe)","evil-twin":"var(--orange)","dns-hijack":"var(--bad)"};
let consented = false;

function gradeColor(g){return {A:"#2ecc71",B:"#9be15d",C:"#ffc233",D:"#ff8a3d",F:"#ff4d5e"}[g]||"#8fa3c8";}
function riskColor(r){ if(r<10)return"#2ecc71"; if(r<30)return"#9be15d"; if(r<50)return"#ffc233"; if(r<70)return"#ff8a3d"; return"#ff4d5e"; }
function sevTextColor(s){ return (s==="Critical"||s==="High") ? "#ffffff" : "#07122e"; }
function el(t,c,txt){const e=document.createElement(t); if(c)e.className=c; if(txt!=null)e.textContent=txt; return e;}
function esc(s){const d=document.createElement("div"); d.textContent=s==null?"":String(s); return d.innerHTML;}

const DEMO_LABELS={"safe-cafe":"safe network","evil-twin":"evil twin","dns-hijack":"dns hijack"};
async function loadScenarios(){
  const box=document.getElementById("chips");
  try{
    const r=await fetch("/api/scenarios"); const list=await r.json();
    list.forEach(s=>{
      const c=el("button","chip");
      const dot=el("span","dot"); dot.style.background=DEMO_DOTS[s.name]||"var(--muted)";
      c.appendChild(dot);
      c.appendChild(el("span",null,DEMO_LABELS[s.name]||s.name.replace(/-/g," ")));
      c.appendChild(el("small",null,s.expected));
      c.onclick=()=>runDemo(s.name);
      box.appendChild(c);
    });
  }catch(e){ box.appendChild(el("span","eyebrow","examples unavailable")); }
}

async function runDemo(name){
  setBusySteps("Running scenario: "+name.replace(/-/g," "));
  try{
    const r=await fetch("/api/demo?scenario="+encodeURIComponent(name));
    if(!r.ok) throw new Error("HTTP "+r.status);
    render(await r.json());
  }catch(e){ showError("Could not run scenario", e.message); }
}

/* ---- guided scan progress panel (friendlier, explains each step) ---- */
const SCAN_STEPS=[
  "Reading your network's name and details",
  "Checking the Wi-Fi lock (encryption)",
  "Looking for fake copies of this network",
  "Verifying your website lookups (DNS)",
  "Watching for a middleman (ARP / gateway)",
  "Probing your padlock (HTTPS) connections",
  "Checking for login and terms pages",
  "Checking your own device's exposure",
  "Comparing with your past visits (history)",
  "Checking if a VPN is shielding you"
];
let busyToken=0, stepTimer=null;

function setRadar(scanning){
  const sc=document.getElementById("scanner"); if(sc) sc.classList.toggle("scanning", scanning);
  const rs=document.getElementById("radarState");
  if(rs) rs.textContent=scanning?"SCANNING — 9 CHECKS IN PROGRESS":"STANDBY — PRESS SCAN";
}
function clearBusy(){
  if(stepTimer){ clearTimeout(stepTimer); stepTimer=null; }
  busyToken++;
  setRadar(false);
}

function setBusySteps(msg){
  const e=document.getElementById("empty"); if(e) e.style.display="none";
  document.getElementById("result").style.display="none";
  clearBusy();
  setRadar(true);
  const token=++busyToken;
  const rows=SCAN_STEPS.map((t,i)=>
    `<div class="sp-step pending" id="sp${i}"><span class="no">${i+1}</span>`+
    `<span class="tx">${esc(t)}</span><span class="ic">·</span></div>`).join("");
  document.getElementById("status").innerHTML=
    `<div class="scan-progress">
       <div class="sp-head">
         <div class="sp-radar"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7v5l3.5 2"/></svg></div>
         <div><div class="sp-title">${esc(msg||"Scanning this network")}</div>
              <div class="sp-sub">Watching each layer of protection as it's checked…</div></div>
       </div>
       <div class="sp-steps">${rows}</div>
     </div>`;
  let cur=-1;
  const tick=()=>{
    if(token!==busyToken) return;                 // a newer scan took over
    if(cur>=0){
      const p=document.getElementById("sp"+cur);
      if(p){ p.classList.remove("now"); p.classList.add("done");
             const ic=p.querySelector(".ic"); if(ic) ic.textContent="✓"; }
    }
    cur=(cur+1)%SCAN_STEPS.length;
    const el=document.getElementById("sp"+cur);
    if(el){ el.classList.remove("pending"); el.classList.add("now");
            const ic=el.querySelector(".ic"); if(ic) ic.textContent=""; }
    stepTimer=setTimeout(tick, 850);
  };
  stepTimer=setTimeout(tick, 850);
}
function showError(title,detail){
  clearBusy();
  document.getElementById("status").innerHTML=
    `<div class="errbox"><b>${esc(title)}</b><p>${esc(detail||"")}</p></div>`;
}

function doScan(){
  const offline=document.getElementById("offline");
  setBusySteps("Assessing this network");
  fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({offline: offline?offline.checked:false})})
    .then(r=>{ if(!r.ok) return r.json().then(j=>{throw new Error(j.error||("HTTP "+r.status));}); return r.json(); })
    .then(render)
    .catch(e=>showError("Scan failed", e.message));
}
function requestScan(){ if(consented){doScan();return;} document.getElementById("scrim").classList.add("show"); }

const SHIELD = {
  safe:'<svg viewBox="0 0 24 24" fill="none" stroke="#35d07f" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
  caution:'<svg viewBox="0 0 24 24" fill="none" stroke="#f4b942" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M12 9v4"/><circle cx="12" cy="16" r=".6" fill="#f4b942" stroke="none"/></svg>',
  avoid:'<svg viewBox="0 0 24 24" fill="none" stroke="#ff5d52" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/></svg>'
};
const TASK_ICON = {safe:"✓", careful:"!", avoid:"✕"};
// friendly framing for each technical dimension: a plain question + a short,
// plain one-liner for each of the four possible states.
const CHECK_META = {
  encryption:{q:"Is the Wi-Fi itself locked?",
    safe:"Locked — people nearby can't read your traffic.",
    danger:"This Wi-Fi is open — people nearby could see your traffic.",
    heads:"Weak Wi-Fi security — treat it like an open network.",
    cant:"Couldn't check the Wi-Fi lock here."},
  ssid_legitimacy:{q:"Is this the real network, not a fake?",
    safe:"No fake copies of this network were spotted.",
    danger:"A possible fake copy of this network is nearby.",
    heads:"Something about the nearby network names looks off.",
    cant:"Couldn't check for fake networks here."},
  dns_integrity:{q:"Are you reaching the real websites?",
    safe:"Your website lookups matched a trusted source.",
    danger:"You may be redirected to fake websites.",
    heads:"Your website lookups look slightly off.",
    cant:"Couldn't double-check your website lookups here."},
  arp_behaviour:{q:"Is anyone secretly in the middle?",
    safe:"No sign of anyone intercepting your connection.",
    danger:"Signs that someone is in the middle of your connection.",
    heads:"Something about the local network looks unusual.",
    cant:"Couldn't check for a middleman here."},
  transport_security:{q:"Are your padlock (HTTPS) pages private?",
    safe:"Your secure connections tested as private.",
    danger:"Your secure connections may be getting read.",
    heads:"Secure connections look slightly off.",
    cant:"Couldn't confirm your secure connections here."},
  captive_portal:{q:"Is the login / terms page safe?",
    safe:"No risky login page in the way.",
    danger:"The login page isn't secure — don't enter real passwords.",
    heads:"There's a login page served over plain HTTP.",
    cant:"Couldn't check the login page here."},
  device_exposure:{q:"Is your own device exposed?",
    safe:"Your device isn't sharing risky services.",
    danger:"Your device is exposing risky services others here could reach.",
    heads:"Your device is sharing something others could reach.",
    cant:"Couldn't fully check your device's exposure here."},
  network_history:{q:"Has this network changed since last time?",
    safe:"This network matches what you saw before.",
    danger:"This network changed suspiciously since last time.",
    heads:"Something about this network changed since last time.",
    cant:"No history yet — a baseline was saved for next time."},
  vpn_presence:{q:"Are you shielded by a VPN?",
    safe:"A VPN is on — strong protection on any network.",
    danger:"", heads:"",
    cant:"No VPN detected — turning one on adds strong safety."}
};
const PILL={safe:{t:"Safe",c:"good"},heads:{t:"Heads-up",c:"warn"},
            danger:{t:"Danger",c:"bad"},cant:{t:"Can't tell",c:"skip"}};
const STATUS_MARK={safe:"✓",heads:"!",danger:"✕",cant:"?"};

// subject icons so each check is recognisable at a glance
const CHECK_ICON={
  encryption:'<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  ssid_legitimacy:'<svg viewBox="0 0 24 24"><rect x="4" y="8" width="11" height="11" rx="2"/><path d="M9 8V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2h-2"/></svg>',
  dns_integrity:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.4 2.5 14.6 0 17M12 3.5c-2.5 2.4-2.5 14.6 0 17"/></svg>',
  arp_behaviour:'<svg viewBox="0 0 24 24"><circle cx="7" cy="9" r="2.4"/><circle cx="17" cy="9" r="2.4"/><path d="M3.5 18.5a3.5 4 0 0 1 7 0M13.5 18.5a3.5 4 0 0 1 7 0"/></svg>',
  transport_security:'<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><circle cx="12" cy="11" r="1.4"/><path d="M12 12.4V15"/></svg>',
  captive_portal:'<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9.5h18"/><circle cx="6" cy="7.2" r=".5"/></svg>',
  device_exposure:'<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20M9 16v4M15 16v4"/></svg>',
  network_history:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7v5l3.5 2"/></svg>',
  vpn_presence:'<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
};
const TASK_ICON_SVG={
  browse:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.4 2.5 14.6 0 17M12 3.5c-2.5 2.4-2.5 14.6 0 17"/></svg>',
  login:'<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="3.4"/><path d="M11.2 12H20M17 12v3M20 12v2.2"/></svg>',
  shop:'<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18"/></svg>',
  bank:'<svg viewBox="0 0 24 24"><path d="M4 10l8-5 8 5"/><path d="M5.5 10v7M9.5 10v7M14.5 10v7M18.5 10v7"/><path d="M3.5 20h17"/></svg>'
};

function checkStatus(d){
  if(d.key==="vpn_presence")
    return d.findings.some(f=>f.title.toLowerCase().startsWith("a vpn"))?"safe":"cant";
  if(!d.assessed) return "cant";
  const inconclusive=d.findings.some(f=>
    /could not|couldn'?t|inconclusive|unverified|needs the internet|first visit|baseline recorded|no network name|no exposed services detected/i
      .test((f.title||"")+" "+(f.detail||"")) &&
    (f.severity==="Low"||f.severity==="Info"));
  const w=d.worst_severity;
  if(w==="Critical"||w==="High") return "danger";
  if(w==="Medium") return "heads";
  if(w==="Low")  return inconclusive?"cant":"heads";
  return inconclusive?"cant":"safe";     // Info
}

function render(res){
  clearBusy();
  const emptyEl=document.getElementById("empty"); if(emptyEl) emptyEl.style.display="none";
  document.getElementById("status").innerHTML="";
  document.getElementById("result").style.display="block";

  const A=res.advice||{stance:"caution",headline:"Assessment complete",subhead:"",tasks:[],highlights:[],tips:[]};

  // ---- verdict banner ----
  const banner=document.getElementById("vbanner");
  banner.className="vbanner "+A.stance;
  document.getElementById("vshield").innerHTML=SHIELD[A.stance]||SHIELD.caution;
  document.getElementById("vhead").textContent=A.headline;
  document.getElementById("vsub").textContent=A.subhead;
  document.getElementById("netName").textContent=res.network_name||"—";
  const isDemo=res.mode==="demo";
  document.getElementById("modeName").textContent=isDemo?"example report":"live scan";
  const exb=document.getElementById("exampleBadge"); if(exb) exb.hidden=!isDemo;

  const risk=res.overall_risk;
  document.getElementById("riskNum").textContent=risk;
  // animated score ring + plain-english risk word
  const rm=document.getElementById("ringmeter");
  if(rm){ rm.style.setProperty("--p", risk); rm.style.setProperty("--ringc", riskColor(risk)); }
  const rw=document.getElementById("riskWord");
  if(rw){
    const word= risk<10?"minimal": risk<30?"low": risk<50?"moderate": risk<70?"high":"critical";
    rw.textContent=word+" risk"; rw.className="riskword "+word;
  }
  const gm=document.getElementById("gradeMini"); gm.textContent=res.grade; gm.style.background=gradeColor(res.grade);

  // ---- task cards ----
  const tasks=document.getElementById("tasks"); tasks.innerHTML="";
  (A.tasks||[]).forEach(t=>{
    const c=el("div","task "+t.level);
    const tick=el("div","tick"); tick.innerHTML=TASK_ICON_SVG[t.icon]||STATUS_MARK[t.level]||""; c.appendChild(tick);
    const body=el("div");
    const head=el("div"); head.appendChild(el("span","tname",t.name));
    head.appendChild(el("span","tlevel",t.level==="safe"?"safe":t.level==="careful"?"be careful":"avoid"));
    body.appendChild(head);
    body.appendChild(el("div","treason",t.reason));
    c.appendChild(body); tasks.appendChild(c);
  });

  // ---- friendly checks (plain, one line each) ----
  const checks=document.getElementById("checks"); checks.innerHTML="";
  let nConfirmed=0, nCant=0;
  res.dimensions.forEach(d=>{
    const meta=CHECK_META[d.key]||{q:d.name};
    const st=checkStatus(d);
    if(st==="cant") nCant++; else nConfirmed++;
    const pill=PILL[st];
    const card=el("div","check");
    const top=el("div","ctop");
    const mark=el("div","cmark "+pill.c); mark.innerHTML=CHECK_ICON[d.key]||STATUS_MARK[st]; top.appendChild(mark);
    top.appendChild(el("div","cq",meta.q));
    top.appendChild(el("div","cpill "+pill.c, pill.t));
    card.appendChild(top);

    // short plain sentence for this state (fall back to a finding detail)
    let line=meta[st];
    if(!line){
      const lead=d.findings.find(f=>f.severity!=="Info")||d.findings[0];
      line=lead?lead.detail:"";
    }
    if(line) card.appendChild(el("div","cwhat",line));

    // a short action only when it matters
    if(st==="danger"||st==="heads"){
      const rec=(d.findings.find(f=>f.recommendation)||{}).recommendation;
      if(rec) card.appendChild(el("div","cdo","→ "+rec));
    }

    // full evidence tucked away for report / advanced users
    if(d.findings.length){
      const det=el("details","more");
      det.appendChild(el("summary",null,"technical detail"));
      d.findings.forEach(f=>{
        const tf=el("div","tech-find");
        tf.appendChild(el("div","tt",f.severity+" · "+f.title));
        if(f.detail) tf.appendChild(el("div","td",f.detail));
        if(f.evidence) tf.appendChild(el("div","ev",f.evidence));
        det.appendChild(tf);
      });
      card.appendChild(det);
    }
    checks.appendChild(card);
  });

  // coverage line under the banner — honest about what we could confirm
  const cover=document.getElementById("vcover");
  if(nCant>0){
    cover.innerHTML=`Checked <b>${nConfirmed}</b> of ${nConfirmed+nCant} things on this `+
      `network · <b>${nCant}</b> couldn't be verified here (shown as “Can't tell”).`;
  }else{
    cover.innerHTML=`All <b>${nConfirmed}</b> checks completed on this network.`;
  }

  // ---- tips ----
  const tl=document.getElementById("tipList"); tl.innerHTML="";
  (A.tips||[]).forEach(tip=> tl.appendChild(el("li",null,tip)) );

  // ---- final action plan ----
  const plan=A.action_plan||{can_do:[],avoid:[]};
  const pc=document.getElementById("planCan"); pc.innerHTML="";
  (plan.can_do||[]).forEach(x=> pc.appendChild(el("li",null,x)) );
  const pa=document.getElementById("planAvoid"); pa.innerHTML="";
  if((plan.avoid||[]).length===0){ pa.appendChild(el("li",null,"Nothing to avoid — this network is fine for normal use.")); }
  else (plan.avoid||[]).forEach(x=> pa.appendChild(el("li",null,x)) );

  // ---- technical section: gauge, grade, dimensions, APs ----
  const col=riskColor(risk);
  document.getElementById("riskNum2").textContent=risk;
  const arc=document.getElementById("gaugeArc"); arc.setAttribute("stroke",col);
  requestAnimationFrame(()=>arc.setAttribute("stroke-dasharray", risk+" 100"));
  const gb=document.getElementById("gradeBox"); gb.textContent=res.grade; gb.style.background=gradeColor(res.grade);
  document.getElementById("verdict").textContent=res.verdict;
  document.getElementById("platName").textContent=res.platform||"—";
  document.getElementById("startedAt").textContent=(res.started_at||"").replace("T"," ").replace("+00:00"," UTC");
  const bpl=document.getElementById("bPlat"); if(bpl) bpl.textContent=res.platform||"—";
  const bst=document.getElementById("bStarted"); if(bst) bst.textContent=(res.started_at||"").replace("T"," ").replace("+00:00"," UTC");

  const grid=document.getElementById("dims"); grid.innerHTML="";
  res.dimensions.forEach(d=>{
    const card=el("div","dim"+(d.assessed?"":" na"));
    const top=el("div","top");
    top.appendChild(el("span","name",d.name));
    if(d.assessed){
      const b=el("span","badge",d.worst_severity); b.style.background=SEV_COLOR[d.worst_severity]||"var(--sev-info)";
      b.style.color=sevTextColor(d.worst_severity);
      top.appendChild(b);
    }else{ top.appendChild(el("span","badge","N/A")); }
    top.appendChild(el("span","wt","w="+d.weight));
    card.appendChild(top);

    const bar=el("div","bar"); const fill=el("i"); fill.style.background=riskColor(d.dimension_risk); bar.appendChild(fill); card.appendChild(bar);
    card.appendChild(el("div","risknum","dimension risk "+d.dimension_risk+" / 100"));
    setTimeout(()=>{ fill.style.width=Math.max(2,d.dimension_risk)+"%"; },60);

    const real=d.findings.filter(f=>f.severity!=="Info");
    if(!d.assessed){
      card.appendChild(el("div","clean","⊘ Not assessed in this environment"));
    }else if(real.length===0){
      const ok=el("div","clean"); ok.textContent="✓ No issues detected"; card.appendChild(ok);
      const info=d.findings.find(f=>f.severity==="Info");
      if(info) card.appendChild(el("div","fd",info.detail));
    }else{
      d.findings.forEach(f=>{
        const fd=el("div","finding");
        const fh=el("div","fh");
        const s=el("span","sev",f.severity); s.style.background=SEV_COLOR[f.severity]||"var(--sev-info)";
        s.style.color=sevTextColor(f.severity);
        fh.appendChild(s); fh.appendChild(el("span","ft",f.title)); fd.appendChild(fh);
        if(f.detail) fd.appendChild(el("div","fd",f.detail));
        if(f.evidence) fd.appendChild(el("div","ev",f.evidence));
        if(f.recommendation) fd.appendChild(el("div","rec","→ "+f.recommendation));
        card.appendChild(fd);
      });
    }
    grid.appendChild(card);
  });

  const t=document.getElementById("apTable");
  if(res.access_points && res.access_points.length){
    t.innerHTML="<tr><th>SSID</th><th>BSSID</th><th>Security</th><th>Signal</th></tr>";
    res.access_points.forEach(ap=>{
      const tr=document.createElement("tr");
      const sec=(ap.security||"").toLowerCase();
      let cls="ok", label=ap.security||"—";
      if(!sec||sec.includes("open")||sec.includes("wep")){cls="open";}
      else if(sec.includes("wpa2")||sec.includes("wpa3")){cls="ok";} else {cls="mid";}
      tr.innerHTML=`<td>${esc(ap.ssid||"(hidden)")}</td>
        <td class="mono">${esc(ap.bssid||"—")}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td>
        <td class="mono">${ap.signal!=null?esc(ap.signal):"—"}</td>`;
      t.appendChild(tr);
    });
    t.parentElement.style.display="";
  }else{ t.parentElement.style.display="none"; }

  // staggered entrance for the report cards (CSS animation, delay per card)
  [document.getElementById("tasks"),document.getElementById("checks")].forEach(box=>{
    if(box) Array.from(box.children).forEach((c,i)=>{ c.style.animationDelay=(i*60)+"ms"; });
  });

  document.getElementById("result").scrollIntoView({behavior:"smooth",block:"start"});
}

// wire up
document.getElementById("scanBtn").onclick=requestScan;
const scanAgain=document.getElementById("scanAgain"); if(scanAgain) scanAgain.onclick=requestScan;
(function(){
  const t=document.getElementById("exToggle"), w=document.getElementById("exwrap");
  if(t&&w){ t.onclick=()=>{ const open=w.hidden; w.hidden=!open;
    t.classList.toggle("open",open); }; }
})();
document.getElementById("cCancel").onclick=()=>document.getElementById("scrim").classList.remove("show");
document.getElementById("cAgree").onclick=()=>{consented=true; document.getElementById("scrim").classList.remove("show"); doScan();};
document.getElementById("scrim").onclick=e=>{ if(e.target.id==="scrim") e.currentTarget.classList.remove("show"); };
window.addEventListener("keydown",e=>{ if(e.key==="Escape") document.getElementById("scrim").classList.remove("show"); });

fetch("/api/connection").then(r=>r.json()).then(d=>{
  if(d && d.ssid) document.getElementById("conn").textContent="connected: "+d.ssid;
}).catch(()=>{});
loadScenarios();
