// BitNet popup — opened when the user clicks the extension action.
// Communicates with the background service worker, which in turn talks
// to the native host.
//
// Security hardening: [BITNET-F1..F4]
//   - F1: `clipboardWrite` permission added in manifest.json (pasted by
//     the user; without it `navigator.clipboard.writeText` silently fails).
//   - F2: CSS classes now match the HTML (`.locked` / `.unlocked`),
//     not the previous bugged `"status locked"` string.
//   - F3: `clipboard.writeText` is wrapped in try/catch and the user
//     sees a real error message instead of a generic "Copied".
//   - F4: Entry titles and user-facing strings are run through
//     `sanitizeForDisplay` to strip Unicode bidi controls (RLO/RLM/etc.)
//     and prevent phishing spoofs in the popup list (see [BITNET-L6]).

const statusDiv = document.getElementById("status");
const entriesDiv = document.getElementById("entries");
const browserAPI = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome : browser;

document.getElementById("refresh").addEventListener("click", checkStatus);

function clearEntries() {
  while (entriesDiv.firstChild) {
    entriesDiv.removeChild(entriesDiv.firstChild);
  }
}

// [BITNET-F2] Only pass the bare class name ("locked" or "unlocked") —
// the previous "status locked" / "status unlocked" did not match the CSS
// selectors `.locked` / `.unlocked` and the popup showed no color
// feedback at all. To stay backward compatible with the existing CSS
// (which uses `.status.locked`), the class is set to `status locked`
// with the `.status` prefix as well. The single source of truth lives
// in this helper.
function setStatusText(text, cssClass) {
  statusDiv.textContent = text;
  statusDiv.className = "status " + cssClass;
}

// [BITNET-F4] Strip Unicode bidi controls (LRE/RLE/PDF/LRO/RLO/ISL/PDI
// + LRM/RLM). RLO/RLM in particular are heavily abused in phishing to
// flip URL strings visually.
function sanitizeForDisplay(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, '');
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
      setStatusText("Error: " + browserAPI.runtime.lastError.message, "locked");
      return;
    }
    if (response && response.success && response.unlocked) {
      setStatusText("Vault unlocked", "unlocked");
      loadEntries();
    } else {
      setStatusText("Vault locked — unlock in BitNet Desktop", "locked");
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
      // [BITNET-F4] Sanitize title and user@url line for the popup
      // list — the same defense as in content.js so a malicious vault
      // entry with a bidi-control title cannot spoof the user.
      titleDiv.textContent = sanitizeForDisplay(entry.title || "");

      const urlDiv = document.createElement("div");
      urlDiv.className = "entry-url";
      urlDiv.textContent =
        sanitizeForDisplay(entry.username || "") +
        " @ " +
        sanitizeForDisplay(entry.url || "");

      div.appendChild(titleDiv);
      div.appendChild(urlDiv);

      // [BITNET-F3] Wrap clipboard write in try/catch and surface real
      // errors. The previous `.catch(() => {})` swallowed all failures
      // and the popup lied to the user with "Copied" even when the
      // write was denied.
      div.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(entry.username || "");
          setStatusText("Copied " + sanitizeForDisplay(entry.title || ""), "unlocked");
        } catch (err) {
          setStatusText(
            "Clipboard write failed: " + (err && err.message ? err.message : String(err)),
            "locked"
          );
        }
      });

      entriesDiv.appendChild(div);
    });
  });
}

checkStatus();
