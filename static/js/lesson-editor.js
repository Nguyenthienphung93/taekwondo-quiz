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

  function getOrCreateSaveNotice(editor) {
    let box = editor.querySelector(".lesson-save-notice");
    if (box) return box;

    const header = editor.querySelector(".lesson-editor-header");
    const form = editor.querySelector(".lesson-editor-body");

    box = document.createElement("div");
    box.className = "lesson-save-notice";
    box.style.display = "none";

    if (header && form) {
      form.parentNode.insertBefore(box, form);
    } else {
      editor.appendChild(box);
    }

    return box;
  }

  function showSaveNotice(editor, message, type = "success") {
    const box = getOrCreateSaveNotice(editor);
    if (!box) return;

    box.textContent = message;
    box.classList.remove("success", "error", "show");
    box.classList.add(type, "show");
    box.style.display = "block";

    clearTimeout(box._timer);
    box._timer = setTimeout(() => {
      box.classList.remove("show");
      box.style.display = "none";
    }, 2600);
  }

  function enableTitleDragSort(list) {
    if (!list) return;

    if (list.dataset.dragInit === "1") return;
    list.dataset.dragInit = "1";

    let draggingRow = null;
    let placeholder = null;

    function makePlaceholder(height) {
      const ph = document.createElement("div");
      ph.className = "lesson-title-placeholder";
      ph.style.height = height + "px";
      return ph;
    }

    function onPointerMove(e) {
      if (!draggingRow || !placeholder) return;

      const y = e.clientY;
      const rows = [...list.querySelectorAll(".lesson-title-row")]
        .filter(r => r !== draggingRow);

      let target = null;
      for (const r of rows) {
        const rect = r.getBoundingClientRect();
        const mid = rect.top + rect.height / 2;
        if (y < mid) {
          target = r;
          break;
        }
      }

      if (!target) list.appendChild(placeholder);
      else list.insertBefore(placeholder, target);
    }

    function onPointerUp() {
      if (!draggingRow || !placeholder) return;

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

    list.addEventListener("pointerdown", (e) => {
      const handle = e.target.closest(".drag-handle");
      if (!handle) return;

      const row = handle.closest(".lesson-title-row");
      if (!row) return;

      e.preventDefault();

      draggingRow = row;

      const rect = row.getBoundingClientRect();
      placeholder = makePlaceholder(rect.height);

      list.insertBefore(placeholder, row.nextSibling);

      row.classList.add("is-dragging");
      row.style.width = rect.width + "px";
      row.style.pointerEvents = "none";

      document.addEventListener("pointermove", onPointerMove);
      document.addEventListener("pointerup", onPointerUp);
    });
  }

  async function saveSections(editor, btnSave = null) {
    const slug = (editor.dataset.slug || "").trim();
    const rows = editor.querySelectorAll(".lesson-title-row");
    const sections = [];

    rows.forEach(row => {
      const title = row.querySelector(".input-title")?.value.trim() || "";
      const page_raw = row.querySelector(".input-page")?.value.trim() || "";
      if (title) sections.push({ title, page_raw });
    });

    if (!slug) {
      showSaveNotice(editor, "❌ Thiếu slug bài học.", "error");
      return;
    }

    if (btnSave) {
      if (btnSave.dataset.saving === "1") return;
      btnSave.dataset.saving = "1";
      btnSave.disabled = true;
      btnSave.dataset.oldHtml = btnSave.innerHTML;
      btnSave.innerHTML = "⏳";
    }

    try {
      const res = await fetch("/admin/lesson/save-sections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug, sections })
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok || !data.ok) {
        showSaveNotice(
          editor,
          data.error || "❌ Lưu thất bại. Vui lòng thử lại.",
          "error"
        );
        return;
      }

      showSaveNotice(
        editor,
        data.message || "✅ Đã lưu bài học thành công!",
        "success"
      );
    } catch (err) {
      showSaveNotice(editor, "❌ Lỗi mạng khi lưu bài học.", "error");
    } finally {
      if (btnSave) {
        btnSave.disabled = false;
        btnSave.dataset.saving = "0";
        btnSave.innerHTML = btnSave.dataset.oldHtml || "💾";
      }
    }
  }

  function initLessonEditor(editor) {
    if (!editor) return;
    if (editor.dataset.leInit === "1") return;
    editor.dataset.leInit = "1";

    const rtype = (editor.dataset.reviewType || "pdf").toLowerCase();
    const driveKind = (editor.dataset.driveKind || "pdf").toLowerCase();
    const isPdfLike = (rtype === "pdf") || (rtype === "drive" && driveKind === "pdf");

    // luôn tạo sẵn box notice
    getOrCreateSaveNotice(editor);

    if (!isPdfLike) return;

    const list = editor.querySelector("#lessonTitleList");
    if (!list) return;

    if (!list.querySelector(".lesson-title-row")) {
      let sections = [];
      try {
        sections = JSON.parse(editor.dataset.sections || "[]");
      } catch {
        sections = [];
      }

      list.innerHTML = "";

      if (Array.isArray(sections) && sections.length) {
        sections.forEach(sec => createRow(list, sec.title || "", sec.page_raw || ""));
      } else {
        createRow(list);
      }
    }

    enableTitleDragSort(list);
  }

  function getRightPanelBox() {
    return document.getElementById("lessonEditorBox");
  }

  function getCurrentFolder3Id(editor = null) {
    if (editor?.dataset?.folder3Id) {
      return String(editor.dataset.folder3Id).trim();
    }

    const box = getRightPanelBox();
    if (box?.dataset?.folder3Id) {
      return String(box.dataset.folder3Id).trim();
    }

    return "";
  }

  async function reloadLessonRightPanel(folder3Id = "") {
    const box = getRightPanelBox();
    if (!box) return;

    const finalFolder3Id = String(folder3Id || box.dataset.folder3Id || "").trim();

    if (!finalFolder3Id) {
      box.innerHTML = `
        <div class="admin-lesson-right">
          <div id="lessonListBox" class="ui-card">
            <p>❌ Không có Chủ đề 3</p>
          </div>
        </div>
      `;
      return;
    }

    // giữ lại folder3_id để lần sau dùng tiếp
    box.dataset.folder3Id = finalFolder3Id;

    try {
      const res = await fetch(`/admin/lesson/list?folder3_id=${encodeURIComponent(finalFolder3Id)}`);
      const html = await res.text();

      box.innerHTML = `
        <div class="admin-lesson-right">
          <div id="lessonListBox" class="ui-card">
            ${html}
          </div>
        </div>
      `;

      box.dataset.folder3Id = finalFolder3Id;

      if (window.initLessonTypeUI) window.initLessonTypeUI();
    } catch (err) {
      console.error(err);
      box.innerHTML = `
        <div class="admin-lesson-right">
          <div id="lessonListBox" class="ui-card">
            <p>❌ Không tải được danh sách bài học</p>
          </div>
        </div>
      `;
      box.dataset.folder3Id = finalFolder3Id;
    }
  }

  // expose
  window.initLessonEditor = initLessonEditor;
  window.reloadLessonRightPanel = reloadLessonRightPanel;

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

    saveSections(editor, btn);
  });

  // ✅ CLOSE
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-close");
    if (!btn) return;

    const editor = btn.closest(".lesson-editor");
    const folder3Id = getCurrentFolder3Id(editor);

    document.dispatchEvent(new CustomEvent("lesson:editor:close", {
      detail: { folder3Id }
    }));
  });

  // ✅ REMOVE ROW
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-remove, .btn-delete-folder");
    if (!btn) return;

    const row = btn.closest(".lesson-title-row");
    const list = row?.parentElement;
    row?.remove();

    if (list && !list.querySelector(".lesson-title-row")) {
      createRow(list);
    }
  });

  // init khi inject
  document.addEventListener("lesson:loaded", (e) => {
    if (e.detail) initLessonEditor(e.detail);
  });

  // ✅ khi editor đóng → load lại khung phải đúng wrapper để giữ scroll
  document.addEventListener("lesson:editor:close", function(e){
    const folder3Id = e.detail?.folder3Id || "";
    reloadLessonRightPanel(folder3Id);
  });
})();