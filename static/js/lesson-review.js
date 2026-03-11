/* static/js/lesson-review.js
   PDF lesson review controller (sidebar sections + pagination)
*/
(function () {
  "use strict";

  // ===============================
  // Utils
  // ===============================
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
    // Hỗ trợ:
    // "1"
    // "2-5"
    // "2:5"
    // "1,3,5"
    // "1-3,7,9-10"
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

  function pickPdfUrl(lessonData) {
    const u = (lessonData?.pdf_url || "").trim();
    if (u) return u;

    const p = (lessonData?.pdf || "").trim();
    if (!p) return "/static/Bai_hoc.pdf";

    if (
      p.startsWith("http://") ||
      p.startsWith("https://") ||
      p.startsWith("/")
    ) {
      return p;
    }

    return "/static/" + p.replace(/^\/+/, "");
  }

  // ===============================
  // Main
  // ===============================
  document.addEventListener("DOMContentLoaded", async function () {
    const lessonData = window.LESSON_DATA;
    console.log("[lesson review] LESSON_DATA =", lessonData);

    if (!lessonData) {
      console.warn("[lesson review] missing LESSON_DATA");
      return;
    }

    if (!window.pdfjsLib || !window.pdfjsLib.GlobalWorkerOptions) {
      console.warn("[lesson review] pdfjsLib not found.");
      return;
    }

    pdfjsLib.GlobalWorkerOptions.workerSrc =
      "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

    const pdfUrl = pickPdfUrl(lessonData);
    const sections = Array.isArray(lessonData.sections) ? lessonData.sections : [];

    console.log("[lesson review] pdfUrl =", pdfUrl);
    console.log("[lesson review] sections =", sections);

    const canvas = document.getElementById("pdfCanvas");
    const pageInfo = document.getElementById("pageInfo");
    const contentEl =
      document.querySelector(".lesson-content") || canvas?.parentElement;

    if (!canvas || !contentEl) {
      console.warn("[lesson review] canvas or content element missing.");
      return;
    }

    let pdfDoc = null;
    let currentSection = 0;
    let currentIndex = 0;
    let allPagesMode = false;
    let renderToken = 0;

    // ===============================
    // UI helpers
    // ===============================
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

    function clearCanvas() {
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
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

    // ===============================
    // Section/page helpers
    // ===============================
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

    // ===============================
    // Render
    // ===============================
    async function renderPage(pdfPageNumber, total) {
      if (!pdfDoc || !canvas || !contentEl) return;

      const myToken = ++renderToken;

      try {
        const safePage = clamp(
          parseInt(pdfPageNumber, 10) || 1,
          1,
          pdfDoc.numPages || 1
        );

        const page = await pdfDoc.getPage(safePage);

        if (myToken !== renderToken) return;

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const availW = Math.max(200, contentEl.clientWidth - 24);
        const availH = Math.max(200, contentEl.clientHeight - 24);

        const pageRotation = page.rotate || 0;

        const vp0 = page.getViewport({
          scale: 1,
          rotation: pageRotation
        });

        let scale = Math.min(availW / vp0.width, availH / vp0.height);
        scale *= 0.98;

        const viewport = page.getViewport({
          scale,
          rotation: pageRotation
        });

        const dpr = window.devicePixelRatio || 1;

        canvas.width = Math.floor(viewport.width * dpr);
        canvas.height = Math.floor(viewport.height * dpr);

        canvas.style.width = `${Math.floor(viewport.width)}px`;
        canvas.style.height = `${Math.floor(viewport.height)}px`;

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const renderTask = page.render({
          canvasContext: ctx,
          viewport
        });

        await renderTask.promise;

        if (myToken !== renderToken) return;

        currentIndex = clamp(currentIndex, 0, Math.max(0, total - 1));
        setPageInfo(currentIndex + 1, total);
        updateNavButtons(total);
      } catch (err) {
        if (myToken !== renderToken) return;
        console.error("[lesson review] renderPage error:", err);
      }
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
        clearCanvas();
        updateNavButtons(0);
        return;
      }

      requestAnimationFrame(() => {
        renderPage(pages[currentIndex], pages.length);
      });
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

    // ===============================
    // Navigation
    // ===============================
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

      if (currentSection > 0) {
        loadSection(currentSection - 1);
      }
    }

    function nextSection() {
      if (!sections.length || allPagesMode) return;

      if (currentSection < sections.length - 1) {
        loadSection(currentSection + 1);
      }
    }

    // ===============================
    // Fullscreen
    // ===============================
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

    document.addEventListener("fullscreenchange", () => {
      const pages = getCurrentPages();
      if (!pages.length) return;

      const pageNumber = pages[currentIndex] || pages[0];
      renderPage(pageNumber, pages.length);
    });

    // ===============================
    // Keyboard
    // ===============================
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

    // ===============================
    // Expose for inline onclick
    // ===============================
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

    // ===============================
    // Load PDF
    // ===============================
    try {
      pdfDoc = await pdfjsLib.getDocument(pdfUrl).promise;
      console.log("[lesson review] PDF loaded. pages =", pdfDoc.numPages);

      if (!sections.length) {
        const totalPages = pdfDoc.numPages || 0;

        if (totalPages > 0) {
          window.__lessonAllPages = Array.from(
            { length: totalPages },
            (_, i) => i + 1
          );

          allPagesMode = true;
          currentSection = -1;
          currentIndex = 0;

          highlightSection(-1);
          setPageInfo(1, totalPages);

          requestAnimationFrame(() => {
            renderPage(1, totalPages);
          });
        } else {
          setPageInfo(0, 0);
          highlightSection(-1);
          clearCanvas();
          updateNavButtons(0);
        }
        return;
      }

      // Có section => mở section đầu, chỉ render 1 lần
      loadSection(0);
    } catch (err) {
      console.error("[lesson review] PDF load error:", err);
      setPageInfo(0, 0);
      clearCanvas();
      highlightSection(-1);
      updateNavButtons(0);
    }

    // ===============================
    // Resize
    // ===============================
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