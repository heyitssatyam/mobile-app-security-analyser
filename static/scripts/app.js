const fileInput = document.getElementById("file-input");
const analyzeButton = document.getElementById("analyze-button");
const loader = document.querySelector(".loaderRectangle");

fileInput.addEventListener("change", () => {
  analyzeButton.disabled = !fileInput.files.length;
});

analyzeButton.addEventListener("click", () => {
  if (fileInput.files.length > 0) {
    loader.classList.remove("hidden");
    analyzeButton.classList.add("hidden");
  }
});
