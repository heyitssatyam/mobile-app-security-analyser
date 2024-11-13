const fileInput = document.getElementById("file-input");
const analyzeButton = document.getElementById("analyze-button");
const report = document.getElementById("report");

fileInput.addEventListener("change", () => {
  analyzeButton.disabled = !fileInput.files.length;
});

// analyzeButton.addEventListener("click", async () => {
//   const formData = new FormData();
//   formData.append("file", fileInput.files[0]);

//   try {
//     const response = await fetch("/upload", {
//       method: "POST",
//       body: formData,
//     });
//     const result = await response.text();
//     document.getElementById("report").innerHTML = result;
//   } catch (error) {
//     report.textContent = "Error analyzing file: " + error.message;
//   }
// });
