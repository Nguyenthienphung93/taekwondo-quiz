(function () {
  // ✅ chống load trùng
  if (window.__LESSON_EDITOR_JS_LOADED__) return;
  window.__LESSON_EDITOR_JS_LOADED__ = true;

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function createRow(list, title = "", page_raw = "") {
    const row = document.createElement("div");
    row.className = "lesson-title-row";

    // ✅ quan trọng: mặc định KHÔNG cho kéo
    row.draggable = false;

    row.innerHTML = `
      <span class="drag-handle" draggable="true" title="Kéo để đổi vị trí" aria-label="Kéo để đổi vị trí">⋮⋮</span>
      <input class="input-title" placeholder="Tiêu đề" value="${escapeHtml(title)}">
      <input class="input-page" type="text" placeholder="Trang (vd: 1-3, 1:3, 1,3)" value="${escapeHtml(page_raw)}">
      <button type="button" class="ui-icon-btn ui-icon-btn--danger btn-remove">🗑</button>
    `;
    list.appendChild(row);
    return row;
  }

  function enableTitleDragSort(list) {
    if (!list) return;

    // ✅ CHỐNG BIND TRÙNG
    if (list.dataset.dragInit === "1") return;
    list.dataset.dragInit = "1";

    let draggingRow = null;
    let placeholder = null;
    let startY = 0;

    function makePlaceholder(height) {
      const ph = document.createElement("div");
      ph.className = "lesson-title-placeholder";
      ph.style.height = height + "px";
      return ph;
    }

    function onPointerMove(e) {
      if (!draggingRow || !placeholder) return;

      const y = e.clientY;

      // tìm row gần nhất để chèn placeholder
      const rows = [...list.querySelectorAll(".lesson-title-row")]
        .filter(r => r !== draggingRow);

      let target = null;
      for (const r of rows) {
        const rect = r.getBoundingClientRect();
        const mid = rect.top + rect.height / 2;
        if (y < mid) { target = r; break; }
      }

      if (!target) list.appendChild(placeholder);
      else list.insertBefore(placeholder, target);
    }

    function onPointerUp() {
      if (!draggingRow || !placeholder) return;

      // thả: đưa row vào đúng chỗ của placeholder
      list.insertBefore(draggingRow, placeholder);
      placeholder.remove();

      draggingRow.classList.remove("is-dragging");
      draggingRow.style.width = "";
      draggingRow.style.pointerEvents = "";
      draggingRow = null;
      placeholder = null;

      document.removeEventListener("pointermove", onPointerMove);
      document.removeEventListener("pointerup", onPointerUp);
    }

    // Delegation: chỉ bắt đầu kéo khi bấm đúng handle
    list.addEventListener("pointerdown", (e) => {
      const handle = e.target.closest(".drag-handle");
      if (!handle) return;

      const row = handle.closest(".lesson-title-row");
      if (!row) return;

      // tránh kéo khi click vào input
      e.preventDefault();

      draggingRow = row;
      startY = e.clientY;

      const rect = row.getBoundingClientRect();
      placeholder = makePlaceholder(rect.height);

      // chèn placeholder ngay vị trí hiện tại
      list.insertBefore(placeholder, row.nextSibling);

      // style khi kéo
      row.classList.add("is-dragging");
      row.style.width = rect.width + "px";
      row.style.pointerEvents = "none"; // để hit-test ra row bên dưới

      document.addEventListener("pointermove", onPointerMove);
      document.addEventListener("pointerup", onPointerUp);
    });
  }

  async function saveSections(editor) {
    const slug = editor.dataset.slug;
    const rows = editor.querySelectorAll(".lesson-title-row");
    const sections = [];

    rows.forEach(row => {
      const title = row.querySelector(".input-title")?.value.trim() || "";
      const page_raw = row.querySelector(".input-page")?.value.trim() || "";
      if (title) sections.push({ title, page_raw });
    });

    const res = await fetch("/admin/lesson/save-sections", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slug, sections })
    });

    const data = await res.json().catch(() => ({}));
    if (!data.ok) {
      alert("❌ Lỗi: " + (data.error || "Không rõ"));
      return;
    }
    alert("✅ Đã lưu thành công!");
  }

  function initLessonEditor(editor) {
    if (!editor) return;

    if (editor.dataset.leInit === "1") return;
    editor.dataset.leInit = "1";

    const rtype = (editor.dataset.reviewType || "pdf").toLowerCase();
    const driveKind = (editor.dataset.driveKind || "pdf").toLowerCase();

    const isPdfLike = (rtype === "pdf") || (rtype === "drive" && driveKind === "pdf");
    if (!isPdfLike) return;

    const list = editor.querySelector("#lessonTitleList");
    if (!list) return;

    // render nếu chưa có row
    if (!list.querySelector(".lesson-title-row")) {
      let sections = [];
      try { sections = JSON.parse(editor.dataset.sections || "[]"); } catch { sections = []; }

      list.innerHTML = "";

      if (Array.isArray(sections) && sections.length) {
        sections.forEach(sec => createRow(list, sec.title || "", sec.page_raw || ""));
      } else {
        createRow(list); // ✅ luôn có 1 dòng
      }
    }

    enableTitleDragSort(list);
  }

  // expose
  window.initLessonEditor = initLessonEditor;

  // init editor có sẵn
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".lesson-editor").forEach(initLessonEditor);
  });

  // ✅ ADD TITLE
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("#btnAddTitle");
    if (!btn) return;

    const editor = btn.closest(".lesson-editor");
    const list = editor?.querySelector("#lessonTitleList");
    if (!editor || !list) return;

    const row = createRow(list);
    row.querySelector(".input-title")?.focus();
  });

  // ✅ SAVE
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-save");
    if (!btn) return;
    const editor = btn.closest(".lesson-editor");
    if (!editor) return;
    saveSections(editor);
  });

  // ✅ CLOSE
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-close");
    if (!btn) return;
    document.dispatchEvent(new CustomEvent("lesson:editor:close"));
  });

  // ✅ REMOVE ROW (bắt cả 2 class để không “lúc được lúc không”)
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-remove, .btn-delete-folder");
    if (!btn) return;
    btn.closest(".lesson-title-row")?.remove();
  });

  // init khi inject (nếu Ken còn dùng event này)
  document.addEventListener("lesson:loaded", (e) => {
    if (e.detail) initLessonEditor(e.detail);
  });
})();