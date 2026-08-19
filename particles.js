/* Subtle "network" background: drifting nodes joined by faint lines. */
(function(){
  const c=document.getElementById("bg"); if(!c) return;
  const ctx=c.getContext("2d"); let w,h,pts;
  const N=Math.min(70, Math.floor((window.innerWidth*window.innerHeight)/26000));
  function resize(){ w=c.width=window.innerWidth; h=c.height=window.innerHeight;
    pts=Array.from({length:N},()=>({x:Math.random()*w,y:Math.random()*h,
      vx:(Math.random()-.5)*.25,vy:(Math.random()-.5)*.25})); }
  function step(){
    ctx.clearRect(0,0,w,h);
    for(const p of pts){ p.x+=p.vx; p.y+=p.vy;
      if(p.x<0||p.x>w)p.vx*=-1; if(p.y<0||p.y>h)p.vy*=-1; }
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const a=pts[i],b=pts[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy);
        if(d<130){ ctx.strokeStyle="rgba(80,150,255,"+(0.14*(1-d/130))+")"; ctx.lineWidth=1;
          ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); } } }
    for(const p of pts){ ctx.fillStyle="rgba(120,190,255,.42)";
      ctx.beginPath(); ctx.arc(p.x,p.y,1.4,0,7); ctx.fill(); }
    requestAnimationFrame(step);
  }
  const reduce=window.matchMedia&&window.matchMedia("(prefers-reduced-motion:reduce)").matches;
  window.addEventListener("resize",resize); resize();
  if(!reduce) step(); else { ctx.clearRect(0,0,w,h); }
})();
