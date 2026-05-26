# BitNet E2E Tests (Playwright)

## Prerequisites

```bash
cd tests/e2e
npm install
npx playwright install chromium
```

## Running Tests

```bash
# Run all tests
npm test

# Run with UI mode
npm run test:ui

# Run specific test
npx playwright test extension.spec.ts --project=chromium
```

## Test Coverage

- **Popup**: Loads correctly, displays vault status
- **Content Script**: Overlay appears on password field focus, hides on blur
- **Native Messaging**: Verifies `is_unlocked` protocol with `bitnet-native-host.exe`

## Notes

- Tests assume `bitnet-native-host.exe` is built in `target/release/`
- Extension must be loaded unpacked for popup/content tests
- Native host tests require the host binary to exist (skipped otherwise)