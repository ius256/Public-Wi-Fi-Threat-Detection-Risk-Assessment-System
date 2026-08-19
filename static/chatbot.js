/* ================= grounded assistant ================= */
(function(){
  const fab=document.getElementById("asstFab");
  const panel=document.getElementById("asst");
  const closeBtn=document.getElementById("asstClose");
  const body=document.getElementById("asstBody");
  const chipsWrap=document.getElementById("asstChips");
  const form=document.getElementById("asstForm");
  const input=document.getElementById("asstText");
  if(!fab||!panel) return;

  const SUGGESTIONS=["Is it safe to bank here?","Why this grade?","What should I do?","What is an evil twin?"];
  let greeted=false;
  const history=[];   // full conversation for multi-turn context

  function bubble(text, who){
    const b=document.createElement("div");
    b.className="bub "+(who==="me"?"me":"bot");
    if(who==="bot"){
      const parts=String(text).split(/\n+/).map(s=>s.trim()).filter(Boolean);
      if(parts.length){
        parts.forEach(p=>{
          const el=document.createElement("div"); el.className="bub-p"; el.textContent=p;
          b.appendChild(el);
        });
      } else { b.textContent=text; }
    } else { b.textContent=text; }
    body.appendChild(b);
    body.scrollTop=body.scrollHeight;
    return b;
  }
  function chips(){
    chipsWrap.innerHTML="";
    SUGGESTIONS.forEach(s=>{
      const c=document.createElement("button"); c.className="asst-chip"; c.type="button"; c.textContent=s;
      c.onclick=()=>{ ask(s); };
      chipsWrap.appendChild(c);
    });
  }
  function open(){
    panel.hidden=false; fab.style.display="none";
    if(!greeted){
      greeted=true;
      bubble("Hi! I'm the PWTDS assistant — the helper inside this Wi‑Fi security scanner. Ask me about the tool itself, your scan, or staying safe on Wi‑Fi — in your own words.", "bot");
      chips();
    }
    setTimeout(()=>input.focus(), 50);
  }
  function close(){ panel.hidden=true; fab.style.display=""; }

  let offlineHintShown=false;

  async function ask(text){
    if(!text) return;
    bubble(text, "me");
    history.push({role:"user", content:text});
    input.value="";
    const thinking=document.createElement("div");
    thinking.className="bub bot typing"; thinking.setAttribute("aria-label","Assistant is typing");
    thinking.innerHTML="<span></span><span></span><span></span>";
    body.appendChild(thinking);
    body.scrollTop=body.scrollHeight;
    try{
      const r=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},
                                       body:JSON.stringify({question:text, history:history.slice(0,-1)})});
      const d=await r.json();
      thinking.remove();
      bubble(d.answer||"Sorry, I didn't catch that.", "bot");
      history.push({role:"assistant", content:d.answer||""});
      if(d.mode==="offline" && !offlineHintShown){
        offlineHintShown=true;
        const note=d.configured
          ? "⚡ Google's free AI is momentarily busy (free-tier limit) — showing the local answer for now; it returns on the next message."
          : "💡 I'm in offline mode right now (built-in answers). To chat freely about anything, add a free AI key in llm_config.json — see the README.";
        const n=bubble(note, "bot");
        n.style.opacity="0.8"; n.style.fontSize="12.5px";
      }
    }catch(e){
      thinking.remove();
      bubble("I couldn't reach the assistant just now.", "bot");
    }
  }

  fab.onclick=open;
  closeBtn.onclick=close;
  const expandBtn=document.getElementById("asstExpand");
  if(expandBtn){
    expandBtn.onclick=()=>{
      const max=panel.classList.toggle("max");
      expandBtn.setAttribute("aria-label", max?"Shrink chat":"Expand to 60% of the screen");
      expandBtn.title=max?"Shrink chat":"Expand to 60% of the screen";
    };
  }
  form.addEventListener("submit", e=>{ e.preventDefault(); ask(input.value.trim()); });
})();
