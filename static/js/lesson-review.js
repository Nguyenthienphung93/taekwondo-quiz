/* static/js/admin_review.js
   PDF review page controller (sidebar sections + pagination)
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
    // Supports: "1", "2-5", "2:5", "1,3,5", "1-3,7,9-10"
    if (!raw) return [];
    const cleaned = String(raw).replace(/\s+/g, "");
    if (!cleaned) return [];

    const out = new Set();

    cleaned.split(",").forEach((part) => {
      if (!part) return;

      // range: "-" or ":"
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
    if (p) return "/static/" + p.replace(/^\/+/, "");

    return "/static/Bai_hoc.pdf";
  }

  // ===============================
  // Main
  // ===============================
  document.addEventListener("DOMContentLoaded", async function () {
    const lessonData = window.LESSON_DATA;
    if (!lessonData) return;

    // PDF.js worker
    if (!window.pdfjsLib || !window.pdfjsLib.GlobalWorkerOptions) {
      console.warn("[admin_review] pdfjsLib not found.");
      return;
    }
    pdfjsLib.GlobalWorkerOptions.workerSrc =
      "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

    const pdfUrl = pickPdfUrl(lessonData);
    const sections = Array.isArray(lessonData.sections) ? lessonData.sections : [];

    const canvas = document.getElementById("pdfCanvas");
    const pageInfo = document.getElementById("pageInfo"); // optional fallback
    const contentEl =
      document.querySelector(".lesson-content") || canvas?.parentElement;

    let pdfDoc = null;
    let currentSection = 0; // index in sections[]
    let currentIndex = 0;   // index in pages[] of that section

    // ✅ CHỈ GIỮ 1 HÀM setPageInfo
    function setPageInfo(now, total) {
      const nowEl = document.getElementById("pageNow");
      const totalEl = document.getElementById("pageTotal");

      if (nowEl && totalEl && Number.isFinite(now) && Number.isFinite(total)) {
        nowEl.textContent = String(now);
        totalEl.textContent = String(total);
      } else if (pageInfo) {
        // fallback nếu ai đó còn dùng #pageInfo
        pageInfo.innerText = `${now} / ${total}`;
      }
    }

    function clearCanvas() {
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    function highlightSection(idx) {
      document
        .querySelectorAll(".lesson-sidebar .lesson-nav-btn, .lesson-sidebar button")
        .forEach((b, i) => b.classList.toggle("active", i === idx));
    }

    function getSectionPages(idx) {
      const sec = sections[idx];
      if (!sec) return [];

      // 1) backend trả mảng sec.pages = [2,3,4] hoặc ["2-4"]
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

      // 2) backend trả chuỗi sec.pages = "2-4"
      if (typeof sec.pages === "string" && sec.pages.trim()) {
        return parsePages(sec.pages.trim());
      }

      // 3) fallback các key khác
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

    async function renderPage(pdfPageNumber, total) {
      if (!pdfDoc || !canvas) return;

      try {
        const page = await pdfDoc.getPage(pdfPageNumber);
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        // available area
        const availW = Math.max(320, (contentEl?.clientWidth || 800) - 24);
        const availH = Math.max(320, (contentEl?.clientHeight || 600) - 24);

        const vp0 = page.getViewport({ scale: 1 });

        // Fit height first
        let scale = availH / vp0.height;
        // If overflow width -> fit width
        if (vp0.width * scale > availW) scale = availW / vp0.width;

        scale = scale * 1.005;

        const viewport = page.getViewport({ scale });

        canvas.width = Math.floor(viewport.width);
        canvas.height = Math.floor(viewport.height);

        await page.render({ canvasContext: ctx, viewport }).promise;

        currentIndex = clamp(currentIndex, 0, Math.max(0, total - 1));

        // ✅ ĐÚNG: cập nhật pageNow/pageTotal
        setPageInfo(currentIndex + 1, total);
        updateNavButtons(total);
      } catch (err) {
        console.error("[admin_review] renderPage error:", err);
      }
    }

    function loadSection(idx) {
      if (!sections.length) return;

      currentSection = clamp(idx, 0, sections.length - 1);
      currentIndex = 0;

      highlightSection(currentSection);

      const pages = getSectionPages(currentSection);

      if (!pages.length) {
        setPageInfo(0, 0);
        clearCanvas();
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

      // Trang đầu
      if (currentIndex === 0) {
        btnPrev.classList.add("disabled");
        btnPrev.disabled = true;
      } else {
        btnPrev.classList.remove("disabled");
        btnPrev.disabled = false;
      }

      // Trang cuối
      if (currentIndex === total - 1) {
        btnNext.classList.add("disabled");
        btnNext.disabled = true;
      } else {
        btnNext.classList.remove("disabled");
        btnNext.disabled = false;
      }
    }

    function prevPage() {
      const pages = getSectionPages(currentSection);
      if (!pages.length) return;

      if (currentIndex > 0) {
        currentIndex--;
        renderPage(pages[currentIndex], pages.length);
      } else {
        // vẫn update để chắc UI đúng
        setPageInfo(1, pages.length);
      }
    }

    function nextPage() {
      const pages = getSectionPages(currentSection);
      if (!pages.length) return;

      if (currentIndex < pages.length - 1) {
        currentIndex++;
        renderPage(pages[currentIndex], pages.length);
      } else {
        // vẫn update để chắc UI đúng
        setPageInfo(pages.length, pages.length);
      }
    }

    // Expose for inline onclick
    window.loadSection = loadSection;
    window.prevPage = prevPage;
    window.nextPage = nextPage;

    window.closeLesson = function () {
      if (window.history.length > 1) window.history.back();
      else window.close();
    };

    // Load PDF
    try {
      pdfDoc = await pdfjsLib.getDocument(pdfUrl).promise;

      if (!sections.length) {
        setPageInfo(0, 0);
        highlightSection(-1);
        clearCanvas();
        return;
      }

      loadSection(0);
    } catch (err) {
      console.error("[admin_review] PDF load error:", err);
      setPageInfo(0, 0);
      clearCanvas();
      highlightSection(-1);
      return;
    }

    // Re-render on resize (keep current page)
    window.addEventListener(
      "resize",
      debounce(() => {
        const pages = getSectionPages(currentSection);
        if (!pages.length) return;
        const pageNumber = pages[currentIndex] || pages[0];
        renderPage(pageNumber, pages.length);
      }, 180)
    );
  });
})();