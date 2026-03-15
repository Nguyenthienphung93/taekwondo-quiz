document.addEventListener("click", function(e){

  const btn = e.target.closest("[data-folder-action]");
  if(!btn) return;

  const modal = document.getElementById("eduModal");
  if(!modal) return;

  const level = btn.dataset.level;
  const action = btn.dataset.folderAction;

  document.getElementById("eduLevel").value = level;
  document.getElementById("eduMode").value = action;

  document.getElementById("eduModalTitle").innerText =
    action === "add"
      ? "➕ Thêm chủ đề cấp " + level
      : "✏️ Sửa chủ đề cấp " + level;

  modal.classList.add("show");
});


document.getElementById("eduCloseBtn")
  ?.addEventListener("click", closeEduModal);

document.getElementById("eduCancel")
  ?.addEventListener("click", closeEduModal);

function closeEduModal(){
  document.getElementById("eduModal")
    ?.classList.remove("show");
}