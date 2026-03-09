function closeLesson(){
  window.history.back();
}

function fmtTime(sec){
  sec = Math.max(0, Math.floor(sec || 0));
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${String(s).padStart(2,"0")}`;
}

let player = null;
let poll = null;
let duration = 0;

window.onYouTubeIframeAPIReady = function(){
  player = new YT.Player("ytPlayer", {
    events: {
      onReady: () => {
        duration = player.getDuration();
        document.getElementById("ytDur").textContent = fmtTime(duration);

        poll = setInterval(() => {
          if (!player) return;
          const cur = player.getCurrentTime();
          document.getElementById("ytTime").textContent = fmtTime(cur);

          if (duration > 0) {
            document.getElementById("ytProgress").value = Math.floor((cur / duration) * 1000);
          }
        }, 250);
      }
    }
  });
};

function ytToggle(){
  if (!player) return;
  const st = player.getPlayerState();
  if (st === YT.PlayerState.PLAYING) player.pauseVideo();
  else player.playVideo();
}

function ytSeek(delta){
  if (!player) return;
  const cur = player.getCurrentTime();
  player.seekTo(Math.max(0, cur + delta), true);
}

function ytScrub(val){
  if (!player) return;
  const d = player.getDuration();
  if (!d) return;
  const t = (Number(val) / 1000) * d;
  player.seekTo(t, true);
}

function ytFullscreen(){
  const box = document.querySelector(".video-frame");
  if (!box) return;

  if (document.fullscreenElement) document.exitFullscreen();
  else box.requestFullscreen?.();
}

function loadSection(idx){
  const s = (window.LESSON_SECTIONS || [])[idx];
  if (!s || !player) return;

  const t = s.time ?? s.t ?? s.sec;
  if (t != null) {
    player.seekTo(Number(t), true);
    player.playVideo();
  }
}