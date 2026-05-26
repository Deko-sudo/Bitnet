(function () {
  const browserAPI = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome : browser;
  const PASSWORD_SELECTOR = 'input[type="password"]';
  const USERNAME_SELECTOR = 'input[type="text"], input[type="email"], input:not([type])';

  function findPasswordField() {
    return document.querySelector(PASSWORD_SELECTOR);
  }

  function findUsernameField() {
    const passwordField = findPasswordField();
    if (!passwordField) return null;
    const form = passwordField.closest("form");
    if (form) {
      const inputs = form.querySelectorAll(USERNAME_SELECTOR);
      for (const input of inputs) {
        if (input !== passwordField) return input;
      }
    }
    const allInputs = Array.from(document.querySelectorAll("input"));
    const pwdIndex = allInputs.indexOf(passwordField);
    if (pwdIndex > 0) return allInputs[pwdIndex - 1];
    return null;
  }

  function showOverlay(passwordField) {
    const rect = passwordField.getBoundingClientRect();
    const overlay = document.createElement("div");
    overlay.id = "bitnet-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: ${rect.bottom + window.scrollY + 4}px;
      left: ${rect.left + window.scrollX}px;
      background: white;
      border: 1px solid #ccc;
      border-radius: 6px;
      padding: 8px 12px;
      z-index: 999999;
      box-shadow: 0 2px 12px rgba(0,0,0,0.25);
      font-family: sans-serif;
      font-size: 13px;
      cursor: pointer;
      color: #333;
      max-width: 240px;
    `;

    // Check vault status and list matching entries
    browserAPI.runtime.sendMessage({ action: "list_entries" }, (response) => {
      if (browserAPI.runtime.lastError) {
        overlay.textContent = "BitNet: unlock vault";
        overlay.addEventListener("click", () => {
          overlay.textContent = "Unlock BitNet desktop app first.";
          setTimeout(() => overlay.remove(), 2000);
        });
        return;
      }

      if (!response || !response.success) {
        overlay.textContent = "BitNet: unlock vault";
        return;
      }

      const entries = JSON.parse(response.data || "[]");
      const hostname = window.location.hostname.toLowerCase();
      const matches = entries.filter(e => e.url && e.url.toLowerCase().includes(hostname));

      if (matches.length === 0) {
        overlay.textContent = "BitNet: no entries for this site";
        overlay.addEventListener("click", () => overlay.remove());
        return;
      }

      if (matches.length === 1) {
        overlay.textContent = `Fill ${matches[0].title}`;
        overlay.addEventListener("click", () => {
          fillEntry(matches[0].uuid, passwordField);
          overlay.remove();
        });
      } else {
        overlay.innerHTML = `<div style="font-weight:bold;margin-bottom:4px;">BitNet entries:</div>`;
        const list = document.createElement("div");
        matches.forEach(m => {
          const row = document.createElement("div");
          row.textContent = m.title;
          row.style.cssText = "padding:4px 0;cursor:pointer;border-bottom:1px solid #eee;";
          row.addEventListener("click", () => {
            fillEntry(m.uuid, passwordField);
            overlay.remove();
          });
          list.appendChild(row);
        });
        overlay.appendChild(list);
      }
    });

    document.body.appendChild(overlay);
    setTimeout(() => {
      if (document.body.contains(overlay)) overlay.remove();
    }, 15000);
  }

  function fillEntry(uuid, passwordField) {
    browserAPI.runtime.sendMessage({ action: "get_password", uuid: uuid }, (response) => {
      if (browserAPI.runtime.lastError || !response || !response.success) {
        console.error("BitNet fill failed:", browserAPI.runtime.lastError?.message || response?.error);
        return;
      }
      const password = response.data;
      passwordField.value = password;
      passwordField.dispatchEvent(new Event("input", { bubbles: true }));
      passwordField.dispatchEvent(new Event("change", { bubbles: true }));

      const usernameField = findUsernameField();
      if (usernameField) {
        // We don't have username in the current native host response,
        // but we could extend the protocol. For now, just fill password.
      }
    });
  }

  document.addEventListener("focus", (e) => {
    if (e.target.matches(PASSWORD_SELECTOR)) {
      // Remove existing overlay before showing new one
      const existing = document.getElementById("bitnet-overlay");
      if (existing) existing.remove();
      showOverlay(e.target);
    }
  }, true);

  document.addEventListener("blur", (e) => {
    if (e.target.matches(PASSWORD_SELECTOR)) {
      const existing = document.getElementById("bitnet-overlay");
      if (existing) existing.remove();
    }
  }, true);
})();
