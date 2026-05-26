const NATIVE_HOST = "com.bitnet.nativehost";

// Chrome/Edge/Firefox compatibility
const browserAPI = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome : browser;

function sendNativeMessage(message) {
  return new Promise((resolve, reject) => {
    browserAPI.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      if (browserAPI.runtime.lastError) {
        reject(new Error(browserAPI.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "get_password") {
    sendNativeMessage({ action: "get_password", uuid: request.uuid })
      .then((response) => sendResponse({ success: true, data: response.data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // keep channel open for async
  }
  if (request.action === "is_unlocked") {
    sendNativeMessage({ action: "is_unlocked" })
      .then((response) => sendResponse({ success: true, unlocked: response.success }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
  if (request.action === "list_entries") {
    sendNativeMessage({ action: "list_entries" })
      .then((response) => sendResponse({ success: true, data: response.data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});