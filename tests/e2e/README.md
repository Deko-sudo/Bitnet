# BitNet Browser Extension — E2E Tests

## Prerequisites

- Node.js >= 18
- Playwright >= 1.60 (`npx playwright install chromium`)
- Extension loaded from `D:\BitNet\bitnet\browser-extension\`

## Running Tests

```bash
cd tests/e2e
npx playwright test
```

## Test Coverage

| Test | Description | Native Host Required |
|------|-------------|---------------------|
| `popup shows locked state` | Lock icon appears when no native host | No |
| `popup shows unlocked state` | Green indicator + entry list via mock | No |
| `content script detects login form` | Username/password/TOTP fields visible | No |
| `autofill overlay appears` | Overlay injects and fills form fields | No (mock) |

## Architecture

All tests use **Playwright** with a **real Chromium browser** loading the unpacked
extension (`browser-extension/`).  Native-host replies are **mocked at the
background-page level** so tests run in CI without `bitnet-native-host.exe`.

To run with a real native host:

1. Build the workspace: `cargo build --release`
2. Install the host: `scripts\install-host.ps1 -ExtensionId YOUR_ID`
3. Remove the mock evaluation in `extension.spec.ts`

## Known Limitations

- URL matching in `content.js` uses `window.location.hostname`.  The test server
  runs on `127.0.0.1`; mock entries return `url: "http://127.0.0.1"`.
- Overlay visibility depends on field detection (`isFieldVisible`) which checks
  pixel size.  Headless mode may behave differently — tests force headed mode.
