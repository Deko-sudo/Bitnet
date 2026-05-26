const statusDiv = document.getElementById("status");
const entriesDiv = document.getElementById("entries");
const browserAPI = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome : browser;

document.getElementById("refresh").addEventListener("click", checkStatus);

function checkStatus() {
  entriesDiv.innerHTML = "";
  browserAPI.runtime.sendMessage({ action: "is_unlocked" }, (response) => {
    if (browserAPI.runtime.lastError) {
      statusDiv.textContent = "Error: " + browserAPI.runtime.lastError.message;
      statusDiv.className = "status locked";
      return;
    }
    if (response && response.success && response.unlocked) {
      statusDiv.textContent = "Vault unlocked";
      statusDiv.className = "status unlocked";
      loadEntries();
    } else {
      statusDiv.textContent = "Vault locked — unlock in BitNet Desktop";
      statusDiv.className = "status locked";
    }
  });
}

function loadEntries() {
  browserAPI.runtime.sendMessage({ action: "list_entries" }, (response) => {
    if (browserAPI.runtime.lastError || !response || !response.success) {
      entriesDiv.innerHTML = "<div style='padding:8px;color:#666;'>No entries found.</div>";
      return;
    }
    const entries = JSON.parse(response.data || "[]");
    if (entries.length === 0) {
      entriesDiv.innerHTML = "<div style='padding:8px;color:#666;'>Vault is empty.</div>";
      return;
    }
    entries.forEach(entry => {
      const div = document.createElement("div");
      div.className = "entry";
      div.innerHTML = `<div class="entry-title">${escapeHtml(entry.title)}</div>
                       <div class="entry-url">${escapeHtml(entry.username)} @ ${escapeHtml(entry.url)}</div>`;
      div.addEventListener("click", () => {
        // Copy username to clipboard and notify
        navigator.clipboard.writeText(entry.username || "").catch(() => {});
        statusDiv.textContent = `Copied ${entry.title}`;
      });
      entriesDiv.appendChild(div);
    });
  });
}

function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

checkStatus();
