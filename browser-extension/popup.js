const statusDiv = document.getElementById("status");
const entriesDiv = document.getElementById("entries");
const browserAPI = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome : browser;

document.getElementById("refresh").addEventListener("click", checkStatus);

function clearEntries() {
  while (entriesDiv.firstChild) {
    entriesDiv.removeChild(entriesDiv.firstChild);
  }
}

function setStatusText(text, cssClass) {
  statusDiv.textContent = text;
  statusDiv.className = cssClass;
}

function createTextDiv(text, cssClass) {
  const div = document.createElement("div");
  div.textContent = text;
  if (cssClass) div.className = cssClass;
  div.style.padding = "8px";
  div.style.color = "#666";
  return div;
}

function checkStatus() {
  clearEntries();
  browserAPI.runtime.sendMessage({ action: "is_unlocked" }, (response) => {
    if (browserAPI.runtime.lastError) {
      setStatusText("Error: " + browserAPI.runtime.lastError.message, "status locked");
      return;
    }
    if (response && response.success && response.unlocked) {
      setStatusText("Vault unlocked", "status unlocked");
      loadEntries();
    } else {
      setStatusText("Vault locked — unlock in BitNet Desktop", "status locked");
    }
  });
}

function loadEntries() {
  browserAPI.runtime.sendMessage({ action: "list_entries" }, (response) => {
    if (browserAPI.runtime.lastError || !response || !response.success) {
      entriesDiv.appendChild(createTextDiv("No entries found.", ""));
      return;
    }
    const entries = JSON.parse(response.data || "[]");
    if (entries.length === 0) {
      entriesDiv.appendChild(createTextDiv("Vault is empty.", ""));
      return;
    }
    entries.forEach(entry => {
      const div = document.createElement("div");
      div.className = "entry";

      const titleDiv = document.createElement("div");
      titleDiv.className = "entry-title";
      titleDiv.textContent = entry.title || "";

      const urlDiv = document.createElement("div");
      urlDiv.className = "entry-url";
      urlDiv.textContent = (entry.username || "") + " @ " + (entry.url || "");

      div.appendChild(titleDiv);
      div.appendChild(urlDiv);

      div.addEventListener("click", () => {
        navigator.clipboard.writeText(entry.username || "").catch(() => {});
        setStatusText("Copied " + (entry.title || ""), "status unlocked");
      });

      entriesDiv.appendChild(div);
    });
  });
}

checkStatus();
