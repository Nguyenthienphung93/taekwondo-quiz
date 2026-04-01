/* static/js/lesson-review.js
   Image lesson review controller
*/
(function () {
  "use strict";

  function clamp(n, a, b) {
    return Math.max(a, Math.min(b, n));
  }

  function debounce(fn, ms) {
    let t = null;
    return function (...args) {
      if (t) clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function parsePages(raw) {
    if (!raw) return [];

    const cleaned = String(raw).replace(/\s+/g, "");
    if (!cleaned) return [];

    const out = new Set();

    cleaned.split(",").forEach((part) => {
      if (!part) return;

      if (part.includes("-") || part.includes(":")) {
        const sep = part.includes("-") ? "-" : ":";
        const [a0, b0] = part.split(sep, 2);

        let a = parseInt(a0, 10);
        let b = parseInt(b0, 10);

        if (!Number.isFinite(a) || !Number.isFinite(b)) return;
        if (a > b) [a, b] = [b, a];

        for (let i = a; i <= b; i++) out.add(i);
        return;
      }

      const n = parseInt(part, 10);
      if (Number.isFinite(n)) out.add(n);
    });

    return Array.from(out)
      .filter((n) => Number.isInteger(n) && n > 0)
      .sort((x, y) => x - y);
  }

  document.addEventListener("DOMContentLoaded", function () {
    const lessonData = window.LESSON_DATA || {};
    const sections = Array.isArray(lessonData.sections) ? lessonData.sections : [];
    const imagePages = Array.isArray(lessonData.image_pages) ? lessonData.image_pages : [];

    const imageEl = document.getElementById("lessonImage");
    const pageInfo = document.getElementById("pageInfo");

    if (!imageEl) {
      console.warn("[lesson review] lessonImage not found.");
      return;
    }

    let currentSection = 0;
    let currentIndex = 0;
    let allPagesMode = false;

    function setPageInfo(now, total) {
      const nowEl = document.getElementById("pageNow");
      const totalEl = document.getElementById("pageTotal");

      if (nowEl && totalEl && Number.isFinite(now) && Number.isFinite(total)) {
        nowEl.textContent = String(now);
        totalEl.textContent = String(total);
      } else if (pageInfo) {
        pageInfo.innerText = `${now} / ${total}`;
      }
    }

    function clearImage() {
      imageEl.removeAttribute("src");
    }

    function highlightSection(idx) {
      document
        .querySelectorAll(".lesson-sidebar .lesson-nav-btn, .lesson-sidebar button")
        .forEach((btn, i) => {
          btn.classList.toggle("active", i === idx);
        });
    }

    function toggleSidebar() {
      const sidebar = document.getElementById("lessonSidebar");
      if (!sidebar) return;
      sidebar.classList.toggle("collapsed");
    }

    function closeSidebar() {
      const sidebar = document.getElementById("lessonSidebar");
      if (!sidebar) return;
      sidebar.classList.add("collapsed");
    }

    function getSectionPages(idx) {
      const sec = sections[idx];
      if (!sec) return [];

      if (Array.isArray(sec.pages) && sec.pages.length) {
        const out = [];
        sec.pages.forEach((x) => {
          if (typeof x === "number") out.push(x);
          else if (typeof x === "string") out.push(...parsePages(x));
        });

        return out
          .map((n) => parseInt(n, 10))
          .filter((n) => Number.isInteger(n) && n > 0);
      }

      if (typeof sec.pages === "string" && sec.pages.trim()) {
        return parsePages(sec.pages.trim());
      }

      const raw =
        sec.page_raw ??
        sec.page ??
        sec.page_range ??
        sec.pageRange ??
        sec.pages_raw ??
        sec.pages_text ??
        sec.pagesText ??
        "";

      return parsePages(raw);
    }

    function getCurrentPages() {
      if (allPagesMode && Array.isArray(window.__lessonAllPages)) {
        return window.__lessonAllPages;
      }
      return getSectionPages(currentSection);
    }

    function renderPage(pageNumber, total) {
      const safePage = clamp(parseInt(pageNumber, 10) || 1, 1, imagePages.length || 1);
      const src = imagePages[safePage - 1];

      if (!src) {
        clearImage();
        setPageInfo(0, 0);
        updateNavButtons(0);
        return;
      }

      imageEl.src = src;
      currentIndex = clamp(currentIndex, 0, Math.max(0, total - 1));
      setPageInfo(currentIndex + 1, total);
      updateNavButtons(total);
    }

    function loadSection(idx) {
      if (!sections.length) return;

      allPagesMode = false;
      currentSection = clamp(idx, 0, sections.length - 1);
      currentIndex = 0;

      highlightSection(currentSection);

      const pages = getSectionPages(currentSection);

      if (!pages.length) {
        setPageInfo(0, 0);
        clearImage();
        updateNavButtons(0);
        return;
      }

      renderPage(pages[currentIndex], pages.length);
    }

    function updateNavButtons(total) {
      const btnPrev = document.getElementById("btnPrev");
      const btnNext = document.getElementById("btnNext");

      if (!btnPrev || !btnNext) return;

      if (total <= 1) {
        btnPrev.classList.add("disabled");
        btnNext.classList.add("disabled");
        btnPrev.disabled = true;
        btnNext.disabled = true;
        return;
      }

      if (currentIndex <= 0) {
        btnPrev.classList.add("disabled");
        btnPrev.disabled = true;
      } else {
        btnPrev.classList.remove("disabled");
        btnPrev.disabled = false;
      }

      if (currentIndex >= total - 1) {
        btnNext.classList.add("disabled");
        btnNext.disabled = true;
      } else {
        btnNext.classList.remove("disabled");
        btnNext.disabled = false;
      }
    }

    function prevPage() {
      const pages = getCurrentPages();
      if (!pages.length) return;

      if (currentIndex > 0) {
        currentIndex--;
        renderPage(pages[currentIndex], pages.length);
      } else {
        setPageInfo(1, pages.length);
        updateNavButtons(pages.length);
      }
    }

    function nextPage() {
      const pages = getCurrentPages();
      if (!pages.length) return;

      if (currentIndex < pages.length - 1) {
        currentIndex++;
        renderPage(pages[currentIndex], pages.length);
      } else {
        setPageInfo(pages.length, pages.length);
        updateNavButtons(pages.length);
      }
    }

    function prevSection() {
      if (!sections.length || allPagesMode) return;
      if (currentSection > 0) loadSection(currentSection - 1);
    }

    function nextSection() {
      if (!sections.length || allPagesMode) return;
      if (currentSection < sections.length - 1) loadSection(currentSection + 1);
    }

    function toggleFullscreen() {
      const el = document.getElementById("lessonContent");
      if (!el) return;

      if (!document.fullscreenElement) {
        if (el.requestFullscreen) {
          el.requestFullscreen().catch((err) => {
            console.error("[lesson review] Fullscreen error:", err);
          });
        }
      } else if (document.exitFullscreen) {
        const p = document.exitFullscreen();
        if (p && typeof p.catch === "function") {
          p.catch((err) => {
            console.error("[lesson review] Exit fullscreen error:", err);
          });
        }
      }
    }

    document.addEventListener("keydown", (e) => {
      const tag = document.activeElement?.tagName || "";
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

      switch (e.key) {
        case "ArrowLeft":
          e.preventDefault();
          prevPage();
          break;
        case "ArrowRight":
          e.preventDefault();
          nextPage();
          break;
        case "ArrowUp":
          e.preventDefault();
          prevSection();
          break;
        case "ArrowDown":
          e.preventDefault();
          nextSection();
          break;
        case "f":
        case "F":
          e.preventDefault();
          toggleFullscreen();
          break;
        case "Escape":
          closeSidebar();
          break;
      }
    });

    window.loadSection = loadSection;
    window.prevPage = prevPage;
    window.nextPage = nextPage;
    window.toggleFullscreen = toggleFullscreen;
    window.toggleSidebar = toggleSidebar;
    window.closeSidebar = closeSidebar;
    window.prevSection = prevSection;
    window.nextSection = nextSection;

    window.closeLesson = function () {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    };

    if (!imagePages.length) {
      clearImage();
      setPageInfo(0, 0);
      updateNavButtons(0);
      return;
    }

    if (!sections.length) {
      const totalPages = imagePages.length;
      window.__lessonAllPages = Array.from({ length: totalPages }, (_, i) => i + 1);
      allPagesMode = true;
      currentSection = -1;
      currentIndex = 0;

      highlightSection(-1);
      renderPage(1, totalPages);
      return;
    }

    loadSection(0);

    window.addEventListener(
      "resize",
      debounce(() => {
        const pages = getCurrentPages();
        if (!pages.length) return;

        const pageNumber = pages[currentIndex] || pages[0];
        renderPage(pageNumber, pages.length);
      }, 180)
    );
  });
})();