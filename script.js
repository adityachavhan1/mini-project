// ImageGuard – Digital Image Forensics Tool
// All image processing happens locally in the browser.
import exifr from "exifr";

// ===== Allowed MIME types and extensions for validation =====
const ALLOWED_TYPES = ["image/jpeg", "image/png"];
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png"];

// ===== State: holds the currently analyzed image data for report generation =====
let currentImage = null; // { file, hash, metadata, width, height, previewUrl }
let compareImageA = null; // { file, hash, previewUrl }
let compareImageB = null; // { file, hash, previewUrl }

// ===== DOM references =====
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const uploadError = document.getElementById("uploadError");
const detailsSection = document.getElementById("detailsSection");
const metadataSection = document.getElementById("metadataSection");
const reportSection = document.getElementById("reportSection");
const preview = document.getElementById("preview");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");
const fileFormat = document.getElementById("fileFormat");
const fileDimensions = document.getElementById("fileDimensions");
const hashValue = document.getElementById("hashValue");
const copyHashBtn = document.getElementById("copyHashBtn");
const metadataContent = document.getElementById("metadataContent");
const downloadReportBtn = document.getElementById("downloadReportBtn");

const dropZoneA = document.getElementById("dropZoneA");
const dropZoneB = document.getElementById("dropZoneB");
const fileInputA = document.getElementById("fileInputA");
const fileInputB = document.getElementById("fileInputB");
const previewA = document.getElementById("previewA");
const previewB = document.getElementById("previewB");
const hashA = document.getElementById("hashA");
const hashB = document.getElementById("hashB");
const compareError = document.getElementById("compareError");
const compareResult = document.getElementById("compareResult");

// ===== ELA DOM references =====
const elaSection = document.getElementById("elaSection");
const elaBtn = document.getElementById("elaBtn");
const elaError = document.getElementById("elaError");
const elaResult = document.getElementById("elaResult");
const elaOriginal = document.getElementById("elaOriginal");
const elaCanvas = document.getElementById("elaCanvas");

// ===== ELA constants =====
const ELA_QUALITY = 0.85; // JPEG recompression quality level

// ===== Utility: validate that a file is an allowed image type =====
function isValidImage(file) {
  const name = file.name.toLowerCase();
  const hasValidExt = ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext));
  return ALLOWED_TYPES.includes(file.type) || hasValidExt;
}

// ===== Utility: format bytes into a human-readable string =====
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

// ===== Generate SHA-256 hash using the Web Crypto API =====
async function generateSHA256(file) {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
  // Convert hash bytes to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ===== Get image dimensions by loading it into an Image element =====
function getImageDimensions(file) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      const dims = { width: img.naturalWidth, height: img.naturalHeight };
      URL.revokeObjectURL(url);
      resolve(dims);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Could not load image"));
    };
    img.src = url;
  });
}

// ===== Extract EXIF metadata using exifr; returns an object or null =====
async function extractMetadata(file) {
  try {
    const data = await exifr.parse(file, { tiff: true, exif: true, gps: true });
    if (!data || Object.keys(data).length === 0) return null;
    return data;
  } catch {
    return null;
  }
}

// ===== Display metadata as a table, or show "unavailable" message =====
function displayMetadata(metadata) {
  if (!metadata) {
    metadataContent.innerHTML =
      '<p class="metadata-empty">No EXIF metadata is available for this image. The image may have been stripped of metadata, reformatted, or was taken by a device that did not embed EXIF data.</p>';
    return;
  }

  // Clean up and format each metadata entry
  const entries = Object.entries(metadata).map(([key, value]) => {
    let displayValue = value;
    if (value instanceof Date) {
      displayValue = value.toLocaleString();
    } else if (typeof value === "object") {
      displayValue = JSON.stringify(value);
    }
    return [key, String(displayValue)];
  });

  // Build a simple table from the entries
  let html =
    '<table class="metadata-table"><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>';
  entries.forEach(([key, value]) => {
    html += `<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(value)}</td></tr>`;
  });
  html += "</tbody></table>";
  metadataContent.innerHTML = html;
}

// ===== Utility: escape HTML to prevent injection when displaying metadata =====
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// ===== Show an error message in a given element =====
function showError(element, message) {
  element.textContent = message;
  element.hidden = false;
}

// ===== Main analysis: validate, preview, extract info, hash, and show metadata =====
async function analyzeImage(file) {
  // Validate file type
  if (!isValidImage(file)) {
    showError(uploadError, "Invalid file type. Please upload a JPG, JPEG, or PNG image.");
    return;
  }

  uploadError.hidden = true;

  try {
    // Generate hash, get dimensions, and extract metadata in parallel
    const [hash, dimensions, metadata] = await Promise.all([
      generateSHA256(file),
      getImageDimensions(file),
      extractMetadata(file),
    ]);

    // Create a preview URL for the uploaded image
    const previewUrl = URL.createObjectURL(file);

    // Store analyzed data for report generation
    currentImage = { file, hash, metadata, width: dimensions.width, height: dimensions.height, previewUrl };

    // Populate the UI
    preview.src = previewUrl;
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    fileFormat.textContent = file.type || "Unknown";
    fileDimensions.textContent = `${dimensions.width} × ${dimensions.height} px`;
    hashValue.textContent = hash;

    displayMetadata(metadata);

    // Reveal hidden sections
    detailsSection.hidden = false;
    elaSection.hidden = false;
    metadataSection.hidden = false;
    reportSection.hidden = false;

    // Reset ELA state for the new image
    elaError.hidden = true;
    elaResult.hidden = true;
  } catch (err) {
    showError(uploadError, "An error occurred while analyzing the image. Please try a different file.");
    console.error(err);
  }
}

// ===== Compare two images by their SHA-256 hashes =====
async function loadCompareImage(file, slot) {
  // Validate file type
  if (!isValidImage(file)) {
    showError(compareError, `Invalid file type for Image ${slot}. Please upload a JPG, JPEG, or PNG image.`);
    return;
  }

  compareError.hidden = true;

  try {
    const hash = await generateSHA256(file);
    const previewUrl = URL.createObjectURL(file);

    // Store hash and preview for the correct slot
    if (slot === "A") {
      compareImageA = { file, hash, previewUrl };
      hashA.textContent = hash;
      previewA.innerHTML = `<img src="${previewUrl}" alt="Image A preview" />`;
      previewA.hidden = false;
    } else {
      compareImageB = { file, hash, previewUrl };
      hashB.textContent = hash;
      previewB.innerHTML = `<img src="${previewUrl}" alt="Image B preview" />`;
      previewB.hidden = false;
    }

    // Run comparison only when both images are loaded
    if (compareImageA && compareImageB) {
      compareHashes();
    }
  } catch (err) {
    showError(compareError, `An error occurred while processing Image ${slot}.`);
    console.error(err);
  }
}

// ===== Compare the two stored hashes and display the result =====
function compareHashes() {
  compareError.hidden = true;

  if (!compareImageA || !compareImageB) {
    showError(compareError, "Please upload both images to compare.");
    return;
  }

  if (compareImageA.hash === compareImageB.hash) {
    compareResult.className = "compare-result match";
    compareResult.innerHTML =
      "<strong>Files are identical</strong>The SHA-256 hashes match exactly. The binary file contents of both images are the same.";
  } else {
    compareResult.className = "compare-result differ";
    compareResult.innerHTML =
      "<strong>Files are different</strong>The SHA-256 hashes do not match. The binary file contents of the two images differ.";
  }
  compareResult.hidden = false;
}

// ===== Generate a downloadable TXT report with all analysis data =====
function downloadReport() {
  if (!currentImage) return;

  const timestamp = new Date().toLocaleString();
  const { file, hash, metadata, width, height } = currentImage;

  let report = "========================================\n";
  report += "   ImageGuard – Analysis Report\n";
  report += "========================================\n\n";
  report += `Analysis Timestamp : ${timestamp}\n`;
  report += `Filename          : ${file.name}\n`;
  report += `File Size         : ${formatBytes(file.size)}\n`;
  report += `Format            : ${file.type || "Unknown"}\n`;
  report += `Dimensions        : ${width} x ${height} px\n`;
  report += `SHA-256 Hash      : ${hash}\n\n`;

  report += "----------------------------------------\n";
  report += "EXIF Metadata\n";
  report += "----------------------------------------\n";
  if (metadata) {
    Object.entries(metadata).forEach(([key, value]) => {
      let displayValue = value;
      if (value instanceof Date) displayValue = value.toLocaleString();
      else if (typeof value === "object") displayValue = JSON.stringify(value);
      report += `${key} : ${displayValue}\n`;
    });
  } else {
    report += "No EXIF metadata available for this image.\n";
  }

  report += "\n----------------------------------------\n";
  report += "Disclaimer\n";
  report += "----------------------------------------\n";
  report += "Metadata and cryptographic hashes alone cannot conclusively establish\n";
  report += "whether an image is authentic or has been manipulated. They are\n";
  report += "supporting indicators only, not proof of integrity.\n";

  // Create a Blob and trigger download
  const blob = new Blob([report], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ImageGuard_Report_${file.name.replace(/\.[^.]+$/, "")}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ===== Error Level Analysis (ELA) =====
// ELA works by recompressing a JPEG at a known quality level and comparing
// pixel differences between the original and recompressed versions.
// Brighter areas in the output indicate higher error (potential editing).
async function performELA() {
  if (!currentImage) return;

  const file = currentImage.file;
  elaError.hidden = true;

  // ELA only works on JPEG images — PNG is lossless so recompression tells us nothing
  const isJPEG = file.type === "image/jpeg" || /\.(jpe?g)$/i.test(file.name);
  if (!isJPEG) {
    showError(elaError, "ELA analysis is only available for JPEG images. PNG files use lossless compression, so recompression comparison is not meaningful.");
    elaResult.hidden = true;
    return;
  }

  try {
    // Load the original image into an Image element to draw on canvas
    const img = await loadImageFromFile(file);
    const w = img.naturalWidth;
    const h = img.naturalHeight;

    // Draw the original image to a canvas and read its pixel data
    const originalCanvas = document.createElement("canvas");
    originalCanvas.width = w;
    originalCanvas.height = h;
    const originalCtx = originalCanvas.getContext("2d");
    originalCtx.drawImage(img, 0, 0);
    const originalData = originalCtx.getImageData(0, 0, w, h);

    // Recompress: export the canvas as JPEG at ELA_QUALITY, then reload it
    const recompressedDataUrl = originalCanvas.toDataURL("image/jpeg", ELA_QUALITY);
    const recompressedImg = await loadImageFromUrl(recompressedDataUrl);

    // Draw the recompressed image to a second canvas and read its pixel data
    const recompCanvas = document.createElement("canvas");
    recompCanvas.width = w;
    recompCanvas.height = h;
    const recompCtx = recompCanvas.getContext("2d");
    recompCtx.drawImage(recompressedImg, 0, 0);
    const recompData = recompCtx.getImageData(0, 0, w, h);

    // Compute per-pixel absolute difference and amplify it for visibility
    const diffData = originalCtx.createImageData(w, h);
    const orig = originalData.data;
    const recomp = recompData.data;
    const diff = diffData.data;

    for (let i = 0; i < orig.length; i += 4) {
      // Amplify the difference by a scale factor to make subtle changes visible
      const scale = 20;
      let dr = Math.abs(orig[i] - recomp[i]) * scale;
      let dg = Math.abs(orig[i + 1] - recomp[i + 1]) * scale;
      let db = Math.abs(orig[i + 2] - recomp[i + 2]) * scale;

      // Clamp to 0-255
      diff[i] = dr > 255 ? 255 : dr;
      diff[i + 1] = dg > 255 ? 255 : dg;
      diff[i + 2] = db > 255 ? 255 : db;
      diff[i + 3] = 255;
    }

    // Display the results
    elaOriginal.src = currentImage.previewUrl;
    elaCanvas.width = w;
    elaCanvas.height = h;
    const elaCtx = elaCanvas.getContext("2d");
    elaCtx.putImageData(diffData, 0, 0);
    elaResult.hidden = false;
  } catch (err) {
    showError(elaError, "An error occurred during ELA analysis. The image may be too large or could not be processed.");
    elaResult.hidden = true;
    console.error(err);
  }
}

// ===== Helper: load a File into an HTMLImageElement =====
function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Failed to load image"));
    };
    img.src = url;
  });
}

// ===== Helper: load a data URL into an HTMLImageElement =====
function loadImageFromUrl(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Failed to load recompressed image"));
    img.src = url;
  });
}

// ===== Wire up the main upload drop zone and file input =====
dropZone.addEventListener("click", () => fileInput.click());
dropZone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});
fileInput.addEventListener("change", (e) => {
  if (e.target.files[0]) analyzeImage(e.target.files[0]);
});

// Drag and drop for main upload zone
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files[0]) analyzeImage(e.dataTransfer.files[0]);
});

// ===== Wire up comparison slots (Image A and Image B) =====
function wireCompareZone(zone, input, slot) {
  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      input.click();
    }
  });
  input.addEventListener("change", (e) => {
    if (e.target.files[0]) loadCompareImage(e.target.files[0], slot);
  });
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("dragover");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer.files[0]) loadCompareImage(e.dataTransfer.files[0], slot);
  });
}

wireCompareZone(dropZoneA, fileInputA, "A");
wireCompareZone(dropZoneB, fileInputB, "B");

// ===== Copy hash to clipboard =====
copyHashBtn.addEventListener("click", async () => {
  if (!currentImage) return;
  try {
    await navigator.clipboard.writeText(currentImage.hash);
    copyHashBtn.textContent = "Copied!";
    setTimeout(() => (copyHashBtn.textContent = "Copy"), 1500);
  } catch {
    copyHashBtn.textContent = "Failed";
    setTimeout(() => (copyHashBtn.textContent = "Copy"), 1500);
  }
});

// ===== Download report button =====
downloadReportBtn.addEventListener("click", downloadReport);

// ===== ELA button =====
elaBtn.addEventListener("click", performELA);
