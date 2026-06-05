(function () {
  const browserAPI = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome : browser;
  const PASSWORD_SELECTOR = 'input[type="password"]';
  const USERNAME_SELECTOR = 'input[type="text"], input[type="email"], input:not([type])';

  // [BITNET-H2] Origin guard. Content script must NOT run on non-HTTPS pages
  // or on private network ranges (localhost / 192.168 / etc.). Manifest now
  // ships the same exclude list, but this runtime check is a defense-in-depth
  // measure in case the manifest is modified by a hostile deployment.
  if (location.protocol !== 'https:') {
    return;
  }
  const h = location.hostname;
  if (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h === '0.0.0.0' ||
    /^10\./.test(h) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(h) ||
    /^192\.168\./.test(h) ||
    /\.local$/.test(h) ||
    /\.internal$/.test(h) ||
    /\.lan$/.test(h) ||
    h.endsWith('.onion')
  ) {
    return;
  }

  // [BITNET-L6] Sanitize entry titles for overlay display. Strips Unicode
  // bidi-control characters (LRE/RLE/PDF/LRO/RLO/ISL/PDI, plus LRM/RLM)
  // so a malicious vault entry like "Google\u202Emooc.kcatta//:sptth" cannot
  // visually spoof the user with a right-to-left override. RLO/RLM in
  // particular are heavily abused in phishing to flip URL strings.
  function sanitizeForDisplay(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, '');
  }

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
      top: ${rect.bottom + 4}px;
      left: ${rect.left}px;
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
        overlay.textContent = `Fill ${sanitizeForDisplay(matches[0].title)}`;
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
          row.textContent = sanitizeForDisplay(m.title);
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
    // uuid is now a 32-char hex string (BitnetCore.cs serializes
    // EntrySummary.uuid via the HexUuid serializer). The native host will
    // route it through bitnet_entry_get_details which expects a hex uuid.
    // [BITNET-L5] Normalize to lowercase before regex matching so an
    // uppercase UUID from a future caller does not silently bypass the
    // validation.
    const normalized = (uuid || '').toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(normalized)) {
      console.error("BitNet: invalid uuid format", uuid);
      return;
    }
    browserAPI.runtime.sendMessage({ action: "get_entry", uuid: normalized }, (response) => {
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
