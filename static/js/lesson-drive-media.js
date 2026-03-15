(function(){
  function fmtTime(sec){
    const n = Number(sec);
    if (!Number.isFinite(n) || n < 0) return "--:--";
    const s0 = Math.floor(n);
    const m  = Math.floor(s0 / 60);
    const s  = s0 % 60;
    return `${m}:${String(s).padStart(2,"0")}`;
  }

  let p = null;
  let seeking = false;

  function init(){
    p = document.getElementById("html5Player");
    if(!p) return;

    const src = window.DRIVE_DIRECT_URL || "";
    if(!src){
      console.warn("[drive-media] DRIVE_DIRECT_URL empty");
      return;
    }

    // video/audio chung
    p.src = src;
    p.preload = "metadata";
    p.controls = false;

    const btnPlay = document.getElementById("btnPlay");
    const vCur = document.getElementById("vCur");
    const vDur = document.getElementById("vDur");
    const seek = document.getElementById("vSeek");

    function setPlayIcon(){
      if(!btnPlay) return;
      btnPlay.textContent = p.paused ? "▶" : "⏸";
    }

    btnPlay?.addEventListener("click", () => {
      if(p.paused) p.play().catch(()=>{});
      else p.pause();
    });

    p.addEventListener("loadedmetadata", () => {
      if(vDur) vDur.textContent = fmtTime(p.duration);
      setPlayIcon();
    });

    p.addEventListener("play", setPlayIcon);
    p.addEventListener("pause", setPlayIcon);

    p.addEventListener("timeupdate", () => {
      if(vCur) vCur.textContent = fmtTime(p.currentTime);
      if(seek && !seeking && p.duration){
        const val = Math.round((p.currentTime / p.duration) * 1000);
        seek.value = String(val);
      }
    });

    // seek bar
    seek?.addEventListener("input", () => { seeking = true; });
    seek?.addEventListener("change", () => {
      if(!p.duration) return;
      const val = Number(seek.value || 0) / 1000;
      p.currentTime = val * p.duration;
      seeking = false;
    });

    // click video để play/pause (chỉ video)
    if(window.DRIVE_KIND === "video"){
      p.addEventListener("click", () => {
        if(p.paused) p.play().catch(()=>{});
        else p.pause();
      });
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();