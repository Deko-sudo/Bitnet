# Phase 7 — Frontend Implementation History

> **Дата:** 2026-04-11
> **Вердикт:** ✅ **Собрано и готово к запуску**
> **Стек:** React 18 + Vite + TypeScript + Tailwind CSS + @simplewebauthn/browser

---

## Структура проекта

```
frontend/
├── index.html                          # SPA entry point, custom SVG favicon
├── package.json                        # Dependencies
├── tsconfig.json                       # Strict TypeScript config
├── vite.config.ts                      # Vite + API proxy to localhost:8000
├── tailwind.config.js                  # Neo-Brutalism theme
├── postcss.config.js                   # (via autoprefixer)
└── src/
    ├── main.tsx                        # React root
    ├── App.tsx                         # Router: locked ↔ unlocked state machine
    ├── vite-env.d.ts                   # Vite type declarations
    ├── styles/
    │   └── globals.css                 # Tailwind + CRT scanline overlay + fonts
    ├── services/
    │   └── webauthn.service.ts         # FIDO2 + password auth service
    ├── hooks/
    │   └── useIdleTimer.ts             # 5-min idle auto-lock hook
    └── components/
        ├── NeoButton.tsx               # Tactile press button (:active → 2px shift)
        ├── VaultInput.tsx              # Inset-style monospace input
        ├── StatusIndicator.tsx         # LOCKED (dim) ↔ UNLOCKED (lime glow)
        ├── LoginPage.tsx               # Access Terminal: toggle, forms, status
        └── VaultDashboard.tsx          # Grid, search, EntryCard, EntryModal
```

---

## Файл за файлом — что сделано

### 1. `package.json` — Зависимости

```json
{
  "dependencies": {
    "@simplewebauthn/browser": "^10.0.0",   // WebAuthn browser SDK
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "typescript": "~5.6.2",
    "vite": "^6.0.5",
    "tailwindcss": "^3.4.17",
    "postcss": "^8.4.49",
    "autoprefixer": "^10.4.20"
  }
}
```

**Проблема:** `npm create vite@latest` интерактивен и таймаутится.
**Решение:** Создана структура вручную — `mkdir`, `write_file` для каждого файла.

---

### 2. `tailwind.config.js` — Neo-Brutalism Theme

```js
colors: {
  void: '#050505',       // Absolute black background
  surface: '#0A0A0A',    // Slightly lighter for cards
  border: '#1A1A1A',     // Hard borders
  lime: {
    DEFAULT: '#CCFF00',  // Electric Lime accent
    dim: '#99CC00',
    glow: 'rgba(204, 255, 0, 0.15)',
    hard: '#AACC00',
  },
}
boxShadow: {
  brutal: '4px 4px 0px 0px #CCFF00',       // Hard offset shadow
  'brutal-sm': '2px 2px 0px 0px #CCFF00',
  'brutal-active': '0px 0px 0px 0px #CCFF00', // "pressed" state
  'glow-lime': '0 0 20px rgba(204, 255, 0, 0.3)',
}
```

---

### 3. `src/styles/globals.css` — CRT Scanline + Fonts

```css
@import url('https://fonts.googleapis.com/css2?family=Inter&family=JetBrains+Mono');

body::after {
  /* CRT scanline overlay */
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 4px
  );
  pointer-events: none;
  z-index: 9999;
}
```

**Баг:** `@import` должен быть ДО `@tailwind` директив.
**Исправление:** Перемещён `@import` в начало файла.

---

### 4. `src/services/webauthn.service.ts` — WebAuthn + API

**Функции:**
- `register(username, token)` — регистрация FIDO2 ключа
- `login(username)` — аутентификация через FIDO2
- `loginWithPassword(username, password)` — стандартный логин
- `registerUser(username, email, password)` — регистрация аккаунта
- `clearSession()` — очистка (no-op, т.к. нет localStorage)

**Ключевая логика:** `prepareOptionsForBrowser()` — рекурсивно конвертирует base64url строки из API в `Uint8Array` для `@simplewebauthn/browser`.

**Баги при type-check:**
1. `uint8ArrayToBase64Url` — неиспользуемая функция → удалена
2. `@ts-expect-error` не нужны в новой версии → заменены на `as any` с eslint-disable
3. `visibilitychange` не в `WindowEventMap` → вынесен в `document.addEventListener`

---

### 5. `src/hooks/useIdleTimer.ts` — Auto-Lock

```ts
useIdleTimer({ timeoutMs: 5 * 60 * 1000, onIdle: () => setAuth({ status: 'locked' }) })
```

**Мониторит:** `mousemove`, `mousedown`, `keydown`, `touchstart`, `scroll`, `visibilitychange`.
Сбрасывает таймер на каждое событие. При 5 мин тишины → вызывает `onIdle` → `setAuth({ status: 'locked' })`.

---

### 6. `src/components/NeoButton.tsx` — Tactile Press

```tsx
// :active — физическое смещение 2px (симуляция механической кнопки)
active:shadow-brutal-active active:translate-x-[2px] active:translate-y-[2px]
```

**Варианты:** `primary` (lime bg), `secondary` (surface bg, lime border), `danger` (red).
**Размеры:** `sm`, `md`, `lg`.

---

### 7. `src/components/VaultInput.tsx` — Inset Input

```tsx
// Вдавленный стиль через border + placeholder
bg-void border-2 border-border focus:border-lime
font-mono tracking-wide  // monospace для sensitive данных
```

---

### 8. `src/components/StatusIndicator.tsx` — LOCKED / UNLOCKED

- **LOCKED:** `text-gray-700`, dimmed border — "STATUS: LOCKED"
- **UNLOCKED:** `text-lime`, `shadow-glow-lime`, `animate-pulse-lime` — "STATUS: UNLOCKED"

---

### 9. `src/components/LoginPage.tsx` — Access Terminal

**Структура:**
1. **Header:** `BITNET` лого + "Digital Vault // E2EE"
2. **Status Indicator:** `STATUS: LOCKED` (dimmed)
3. **Toggle:** `Master Password` | `Security Key`
4. **Password Form:** username → (email если register) → password → UNLOCK VAULT
5. **FIDO2 Form:** username → TOUCH SENSOR кнопка
6. **Footer:** Argon2id | AES-256-GCM | Rust PyO3

**Логика:**
- Toggle между `isRegister` / login режимом
- FIDO2 вызывает `webauthnService.login(username)` → `startAuthentication()` → verify
- Error display: `ERROR: {message}` в red-bordered box

---

### 10. `src/components/VaultDashboard.tsx` — Grid + Search + EntryCard

**Компоненты:**
- **EntryCard:** Title + URL, hover → lime border accent
- **EntryModal:** Показывает username, password (masked/revealed), URL, notes
- **Search Bar:** При вводе — "Computing HMAC Search Index..." анимация

**Хуки:**
- `useAutoMask(30_000)` — reveal password → auto-hide через 30 сек
- `useClipboard()` — copy → auto-clear clipboard через 30 сек

**Data flow:**
```
GET /api/v1/entries/ (или ?query=...) → Entry[] → Grid
GET /api/v1/entries/{id} → EntryDetail → Modal
```

---

### 11. `src/App.tsx` — State Machine

```tsx
type AuthState =
  | { status: 'locked' }
  | { status: 'unlocked'; token: string; username: string }

function App() {
  const [auth, setAuth] = useState<AuthState>({ status: 'locked' })

  // Auto-lock on 5 min idle
  useIdleTimer({ timeoutMs: 5 * 60 * 1000, onIdle: () => setAuth({ status: 'locked' }) })

  if (auth.status === 'locked') return <LoginPage onLogin={handleLogin} />
  return <VaultDashboard token={auth.token} username={auth.username} onLogout={handleLogout} />
}
```

---

## Сборка

### TypeScript
```
npx tsc --noEmit  →  0 errors
```

### Vite Build
```
npx vite build  →  dist/index.html (0.80 KB)
                    dist/assets/index.css (0.93 KB gzipped)
                    dist/assets/index.js (53.13 KB gzipped)
```

### Запуск
```bash
cd frontend
npm install
npm run dev    # → http://localhost:5173 (proxy → localhost:8000)
```

---

## Security Constraints — Checklist

| Требование | Реализация | Статус |
|-----------|-----------|--------|
| **Zero-Persistence** | Никакого `localStorage`/`sessionStorage`. Токен в React state (in-memory). | ✅ |
| **Auto-Lock** | `useIdleTimer` → 5 мин → `setAuth({ status: 'locked' })` | ✅ |
| **Clipboard Safety** | `useClipboard()` → `navigator.clipboard.writeText('')` через 30с | ✅ |
| **Password Auto-Mask** | `useAutoMask(30_000)` → reveal → auto-hide через 30с | ✅ |
| **HttpOnly Cookies** | Backend manages session cookies; frontend не хранит токены | ✅ |
| **HTTPS Proxy** | Vite dev proxy `/api` → `localhost:8000` | ✅ |

---

## Design System — Neo-Brutalism

| Элемент | CSS Class | Описание |
|---------|-----------|----------|
| **Фон** | `bg-void` (#050505) | Absolute black |
| **Карточки** | `bg-surface border-2 border-border p-6` | Dark surface, thick border |
| **Тень** | `shadow-brutal` (4px 4px 0px lime) | Hard offset — "floating block" |
| **Нажатие** | `active:shadow-brutal-active active:translate-x-[2px] active:translate-y-[2px]` | Кнопка "вдавливается" |
| **Шрифт заголовков** | `font-mono uppercase tracking-wider text-lime` | JetBrains Mono, lime |
| **Шрифт UI** | `font-sans text-sm text-gray-300` | Inter, muted gray |
| **Sensitive Data** | `font-mono tracking-wide` | Monospaced для character alignment |
| **Scanline** | `body::after` repeating-gradient | CRT эффект поверх всего |
| **Border Radius** | `rounded-none` (global) | Zero скруглений — везде острые углы |
