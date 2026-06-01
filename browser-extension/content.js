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

  function isFieldVisible(field) {
    const style = window.getComputedStyle(field);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = field.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function showOverlay(passwordField) {
    if (!isFieldVisible(passwordField)) return;
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
      const pageHostname = window.location.hostname.toLowerCase();
      function matchHostname(entryUrl, pageHost) {
        try {
          const u = new URL(entryUrl);
          return u.hostname.toLowerCase() === pageHost;
        } catch (e) { return false; }
      }
      const matches = entries.filter(e => e.url && matchHostname(e.url, pageHostname));

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
        const header = document.createElement("div");
        header.style.cssText = "font-weight:bold;margin-bottom:4px;";
        header.textContent = "BitNet entries:";
        overlay.appendChild(header);

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
    browserAPI.runtime.sendMessage({ action: "get_entry", uuid: uuid }, (response) => {
      if (browserAPI.runtime.lastError || !response || !response.success) {
        console.error("BitNet fill failed:", browserAPI.runtime.lastError?.message || response?.error);
        return;
      }
      var data;
      try { data = JSON.parse(response.data); } catch (e) { return; }
      if (data.password) {
        passwordField.value = data.password;
        passwordField.dispatchEvent(new Event("input", { bubbles: true }));
        passwordField.dispatchEvent(new Event("change", { bubbles: true }));
      }
      var usernameField = findUsernameField();
      if (usernameField && data.username) {
        usernameField.value = data.username;
        usernameField.dispatchEvent(new Event("input", { bubbles: true }));
        usernameField.dispatchEvent(new Event("change", { bubbles: true }));
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

  // Remove overlay on scroll or resize to prevent it from floating at stale coordinates
  window.addEventListener("scroll", () => {
    const existing = document.getElementById("bitnet-overlay");
    if (existing) existing.remove();
  });
  window.addEventListener("resize", () => {
    const existing = document.getElementById("bitnet-overlay");
    if (existing) existing.remove();
  });
})();
