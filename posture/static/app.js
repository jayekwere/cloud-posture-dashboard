"use strict";
const fileInput = document.querySelector("#report-file");
const fileName = document.querySelector("#file-name");
if (fileInput && fileName) {
  fileInput.addEventListener("change", () => {
    fileName.textContent = fileInput.files?.[0]?.name || "Nothing selected yet";
  });
}
for (const button of document.querySelectorAll("[data-confirm]")) {
  button.addEventListener("click", (event) => {
    if (!window.confirm(button.dataset.confirm)) event.preventDefault();
  });
}
