document.addEventListener("click", (event) => {
  const editButton = event.target.closest("[data-edit-target]");
  if (editButton) {
    const targetId = editButton.getAttribute("data-edit-target");
    const form = document.getElementById(targetId);
    if (form) {
      form.classList.toggle("hidden");
    }
    return;
  }

  const deleteForm = event.target.closest("[data-confirm-delete]");
  if (deleteForm && event.target.matches("button")) {
    const confirmed = window.confirm("Delete this note?");
    if (!confirmed) {
      event.preventDefault();
    }
  }
});