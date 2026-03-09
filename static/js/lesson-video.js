/* =========================================================
   lesson-video.js  (Drive video/audio player)
   Requires globals:
   - window.DRIVE_KIND: "video" | "audio" | ...
   - window.DRIVE_DIRECT_URL: string
   - window.LESSON_SECTIONS: array (optional) { time/sec/t ... }
========================================================= */

(function () {
  "use strict";

  // ---------- utils ----------
  function $(id) { return document.getElementById(id); }

  function fmtTime(sec){
    const n = Number(sec);
    if (!Number.isFinite(n) || n < 0) return "--:--";
    const s0 = Math.floor(n);
    const m  = Math.floor(s0 / 60);
    const s  = s0 % 60;
    return `${m}:${String(s).padStart(2,"0")}`;
  }

  function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

  // ---------- state ----------
  let mediaEl = null;              // <video>/<audio>
  let isReady = false;

  // visualizer state
  let audioCtx = null;
  let analyser = null;
  let freqData = null;
  let rafId = null;
  let caps = null;

  // ---------- navigation ----------
  function closeLesson() {
    // giữ y như Ken muốn
    window.history.back();
  }

  // ---------- media init ----------
  function initMedia() {
    const kind = String(window.DRIVE_KIND || "").toLowerCase();
    if (kind !== "video" && kind !== "audio") return;

    mediaEl = $("html5Player");
    if (!mediaEl) return;

    const src = String(window.DRIVE_DIRECT_URL || "").trim();
    if (!src) {
      console.warn("[lesson-video] DRIVE_DIRECT_URL is empty");
      return;
    }

    mediaEl.src = src;
    mediaEl.preload = "metadata";
    mediaEl.controls = false;

  function updateDurationUI(){
    if(!mediaEl) return;

    const dur = (Number.isFinite(mediaEl.duration) && mediaEl.duration > 0)
      ? mediaEl.duration
      : null;

    const durText = dur ? fmtTime(dur) : "--:--";

    const vDur = $("vDur");
    if (vDur) vDur.textContent = durText;

    const metaDur = $("metaDur");
    if (metaDur) metaDur.textContent = durText;
  }

  function fixInfinityDuration(){
    if(!mediaEl) return;

    if (mediaEl.duration === Infinity || !Number.isFinite(mediaEl.duration)) {
      const onTimeUpdate = () => {
        mediaEl.removeEventListener("timeupdate", onTimeUpdate);
        try { mediaEl.currentTime = 0; } catch(_) {}
        updateDurationUI();
      };
      mediaEl.addEventListener("timeupdate", onTimeUpdate);
      try { mediaEl.currentTime = 1e101; } catch(_) {}
    }
  }

    mediaEl.addEventListener("error", () => {
      console.error("[lesson-video] Media error:", mediaEl?.error);
    });

    mediaEl.addEventListener("loadedmetadata", () => {
      isReady = true;

      updateDurationUI();
      fixInfinityDuration();

      fillMetaByHead().catch(() => {});
    });

    // thêm vài event để UI tự cập nhật khi duration đổi
    mediaEl.addEventListener("durationchange", updateDurationUI);
    mediaEl.addEventListener("canplay", updateDurationUI);

    mediaEl.addEventListener("timeupdate", () => {
      if (!mediaEl) return;

      // luôn cập nhật current time
      const t = $("vTime");
      if (t) t.textContent = fmtTime(mediaEl.currentTime);

      // chỉ cập nhật progress khi duration hợp lệ
      if (!Number.isFinite(mediaEl.duration) || mediaEl.duration <= 0) return;

      const p = $("vProgress");
      if (p) p.value = Math.floor((mediaEl.currentTime / mediaEl.duration) * 1000);
    });

    mediaEl.addEventListener("ended", () => {
      // khi end -> đảm bảo UI reset nhẹ
      const p = $("vProgress");
      if (p) p.value = 1000;
    });
  }

  // ---------- controls ----------
  function vToggle() {
    if (!mediaEl) return;
    if (mediaEl.paused) mediaEl.play?.();
    else mediaEl.pause?.();
  }

  function vStop() {
    if (!mediaEl) return;
    mediaEl.pause?.();
    try { mediaEl.currentTime = 0; } catch (_) {}

    const p = $("vProgress");
    if (p) p.value = 0;

    const t = $("vTime");
    if (t) t.textContent = "0:00";

    stopVisualizer(true);
  }

  function vSeek(delta) {
    if (!mediaEl) return;
    const cur = Number(mediaEl.currentTime || 0);
    mediaEl.currentTime = Math.max(0, cur + Number(delta || 0));
  }

  function vScrub(val) {
    if (!mediaEl || !mediaEl.duration) return;
    const ratio = clamp(Number(val || 0) / 1000, 0, 1);
    mediaEl.currentTime = ratio * mediaEl.duration;
  }

  function vFullscreen() {
    const kind = String(window.DRIVE_KIND || "").toLowerCase();
    if (kind !== "video") return;

    const box = document.querySelector(".video-frame");
    if (!box) return;

    if (document.fullscreenElement) document.exitFullscreen?.();
    else box.requestFullscreen?.();
  }

  // sidebar section jump
  function loadSection(idx) {
    const list = Array.isArray(window.LESSON_SECTIONS) ? window.LESSON_SECTIONS : [];
    const s = list[idx];
    if (!s) return;

    const t = s.time ?? s.t ?? s.sec;
    if (t == null || !mediaEl) return;

    mediaEl.currentTime = Math.max(0, Number(t));
    mediaEl.play?.();
  }

  // ---------- meta (name/size) ----------
  async function fillMetaByHead() {
    if (!mediaEl || !mediaEl.src) return;

    const nameEl = $("metaName");
    const sizeEl = $("metaSize");
    if (!nameEl && !sizeEl) return;

    try {
      const res = await fetch(mediaEl.src, { method: "HEAD" });
      const len = res.headers.get("Content-Length");
      const name = res.headers.get("X-File-Name");

      if (nameEl) nameEl.textContent = name || "—";

      if (sizeEl && len) {
        const bytes = Number(len);
        const mb = bytes / (1024 * 1024);
        sizeEl.textContent = mb >= 1024
          ? (mb / 1024).toFixed(2) + " GB"
          : mb.toFixed(2) + " MB";
      } else if (sizeEl) {
        sizeEl.textContent = "—";
      }
    } catch (e) {
      if (nameEl) nameEl.textContent = "—";
      if (sizeEl) sizeEl.textContent = "—";
    }
  }

  // ---------- audio visualizer ----------
  function setupVisualizer() {
    const kind = String(window.DRIVE_KIND || "").toLowerCase();
    if (kind !== "audio") return;
    if (!mediaEl) return;

    const canvas = $("audioViz");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    function resize() {
      const dpr = window.devicePixelRatio || 1;
      const w = Math.max(1, Math.floor(canvas.clientWidth * dpr));
      const h = Math.max(1, Math.floor(canvas.clientHeight * dpr));
      canvas.width = w;
      canvas.height = h;
      // dùng scale theo CSS px
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();
    window.addEventListener("resize", resize);

    function ensureGraph() {
      if (audioCtx) return;
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const src = audioCtx.createMediaElementSource(mediaEl);
      analyser = audioCtx.createAnalyser();
      analyser.fftSize = 256; // 128 bars
      src.connect(analyser);
      analyser.connect(audioCtx.destination);
      freqData = new Uint8Array(analyser.frequencyBinCount);
      caps = new Array(freqData.length).fill(0);
    }

    function roundRect(x, y, w, h, r) {
      const rr = Math.min(r, w / 2, h / 2);
      ctx.beginPath();
      ctx.moveTo(x + rr, y);
      ctx.arcTo(x + w, y, x + w, y + h, rr);
      ctx.arcTo(x + w, y + h, x, y + h, rr);
      ctx.arcTo(x, y + h, x, y, rr);
      ctx.arcTo(x, y, x + w, y, rr);
      ctx.closePath();
    }

    function draw() {
      if (!analyser || !freqData) return;

      analyser.getByteFrequencyData(freqData);

      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      ctx.clearRect(0, 0, w, h);

      const bars = freqData.length; // 128
      const gap = 2;
      const barW = Math.max(2, (w - gap * (bars - 1)) / bars);

      const capFall = 2.6;
      const capH = 6;
      const radius = 3;

      for (let i = 0; i < bars; i++) {
        const v0 = freqData[i] / 255;          // 0..1
        const barH = Math.max(8, v0 * (h * 0.78));
        const x = i * (barW + gap);
        const y = h - barH;

        // rainbow hue
        const hue = (i / bars) * 360;
        const alpha = 0.20 + v0 * 0.85;

        // main bar
        ctx.shadowBlur = 10 * v0;
        ctx.shadowColor = `hsla(${hue}, 100%, 60%, ${alpha})`;
        ctx.fillStyle = `hsla(${hue}, 100%, 55%, ${alpha})`;
        roundRect(x, y, barW, barH, radius);
        ctx.fill();

        // cap
        const capYTarget = y - capH - 2;
        if (caps[i] === 0) caps[i] = capYTarget;
        if (capYTarget < caps[i]) caps[i] = capYTarget;
        else caps[i] += capFall;

        if (caps[i] > h - capH) caps[i] = h - capH;

        ctx.shadowBlur = 0;
        ctx.fillStyle = `hsla(${hue}, 100%, 70%, 0.95)`;
        roundRect(x, caps[i], barW, capH, 3);
        ctx.fill();
      }

      ctx.shadowBlur = 0;
      rafId = requestAnimationFrame(draw);
    }

    function start() {
      ensureGraph();
      if (audioCtx && audioCtx.state === "suspended") audioCtx.resume?.();
      if (!rafId) draw();
    }

    function stop(clear) {
      if (rafId) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }
      if (clear) ctx.clearRect(0, 0, canvas.clientWidth, canvas.clientHeight);
    }

    // hook events
    mediaEl.addEventListener("play", start);
    mediaEl.addEventListener("pause", () => stop(false));
    mediaEl.addEventListener("ended", () => stop(false));

    // expose to outer for stop button
    setupVisualizer._stop = stop;
  }

  function stopVisualizer(clearCanvas) {
    // only for audio
    if (typeof setupVisualizer._stop === "function") {
      setupVisualizer._stop(!!clearCanvas);
    }
  }

  // ---------- export globals (HTML onclick dùng) ----------
  window.closeLesson = closeLesson;
  window.fmtTime = fmtTime;

  window.vToggle = vToggle;
  window.vStop = vStop;
  window.vSeek = vSeek;
  window.vScrub = vScrub;
  window.vFullscreen = vFullscreen;

  window.loadSection = loadSection;

  // ---------- boot ----------
  document.addEventListener("DOMContentLoaded", () => {
    initMedia();
    setupVisualizer();
  });

})();