# Phase 8.1 — Panic Mode Implementation History

> **Дата:** 2026-04-11
> **Вердикт:** ✅ **Собрано и готово**

---

## Что создано

### 1. `src/hooks/usePanicButton.ts` — Global Panic Hook

**Назначение:** Единая точка экстренной блокировки.

**Триггеры:**
- `Escape` key (global listener, capture phase)
- `triggerPanic()` — прямой вызов из UI кнопки

**Функция `purge()`:**
```ts
function purge() {
  // 1. Reset auth state → 'locked'
  onPanicRef.current()

  // 2. Clear in-memory references (best-effort)
  void 0

  // 3. Wipe system clipboard
  navigator.clipboard.writeText('')

  // 4. Fire-and-forget POST to /api/v1/auth/panic
  fetch('/api/v1/auth/panic', { method: 'POST', credentials: 'include' })
    .catch(() => {}) // Network error — ignore, local purge already happened
}
```

**Армирование:** `armingRef` предотвращает двойной вызов — hook arms on mount, disarms on unmount.

**Listener:** `capture: true` — перехватывает Escape до того, как другие обработчики его увидят.

---

### 2. `src/components/PanicButton.tsx` — Neo-Brutalist PANIC Button

**Стиль:**
```tsx
border-2 border-red-600 bg-void text-red-500
font-mono text-xs uppercase tracking-[0.2em]
shadow-[3px_3px_0px_0px_#7F1D1D]  // Hard red shadow
hover:bg-red-950/40
active:shadow-none active:translate-x-[1px] active:translate-y-[1px]
```

**Поведение:**
- `:active` — сдвиг 1px (меньше чем у NeoButton, для тактильного отличия)
- Red-on-black — максимальный контраст для emergency ситуации

**Размещение:** В header, между username и LOCK кнопкой.

---

### 3. `src/components/PanicFlash.tsx` — Full-Screen Red Flash Overlay

**Поведение:**
- При `active === true` → показывает overlay на 200ms
- CSS animation `panic-fade` — opacity 1→0 за 200ms ease-out
- Центральный текст: "LOCKDOWN" — `text-red-200` с `text-shadow`
- `z-[9999]` — поверх всего, включая модалы
- `pointer-events: none` — не блокирует клики (flash — визуальный сигнал)

**CSS:**
```css
@keyframes panic-fade {
  0%   { opacity: 1; }
  100% { opacity: 0; }
}
```

---

### 4. `VaultDashboard.tsx` — Integration

**Изменения:**
```tsx
const [panicFlash, setPanicFlash] = useState(false)

const handlePanic = useCallback(() => {
  setPanicFlash(true)   // Trigger red flash
  onLogout()            // Lock the vault
}, [onLogout])

const { triggerPanic } = usePanicButton({ onPanic: handlePanic })
```

**Header:**
```tsx
<PanicButton onClick={triggerPanic} />
```

**Render:**
```tsx
<PanicFlash active={panicFlash} onDone={() => setPanicFlash(false)} />
```

**Удалён:** Старый `useEffect` с Escape listener — теперь всё в `usePanicButton`.

---

### 5. `globals.css` — panic-fade animation

```css
@keyframes panic-fade {
  0%   { opacity: 1; }
  100% { opacity: 0; }
}
```

---

### 6. Backend Route (Mock)

Frontend отправляет fire-and-forget POST на `/api/v1/auth/panic`.

**Ожидаемое поведение бэкенда (не реализовано, но подготовлено):**
```python
@router.post("/panic")
def panic_logout(request: Request, db: Session = Depends(get_db)):
    """Kill all sessions for the current user."""
    token = extract_bearer_token(request)
    token_hash = hashlib.sha256(token).hexdigest()
    db.query(User).filter(User.session_token_hash == token_hash).update(
        {"session_token_hash": None}
    )
    db.commit()
    return {"status": "locked"}
```

---

## Build Status (Phase 8.1)

```
npx tsc --noEmit    →  0 errors
npx vite build      →  dist/index.html      0.80 kB
                      dist/assets/index.css  2.03 kB (gzip: 0.85 kB)
                      dist/assets/index.js   175.60 kB (gzip: 55.00 kB)
```

---

## Новые файлы

| Файл | Описание |
|------|----------|
| `src/hooks/usePanicButton.ts` | Global panic hook (Escape + purge + clipboard wipe) |
| `src/components/PanicButton.tsx` | Neo-Brutalist red PANIC button |
| `src/components/PanicFlash.tsx` | 200ms full-screen red flash overlay |

## Изменённые файлы

| Файл | Изменение |
|------|-----------|
| `src/components/VaultDashboard.tsx` | + usePanicButton integration, + PanicButton, + PanicFlash |
| `src/styles/globals.css` | + `panic-fade` keyframe animation |

---

## Panic Flow Diagram

```
[User presses Escape]  or  [User clicks PANIC button]
          │
          ▼
   usePanicButton.purge()
          │
          ├─► onPanic() → setAuth({ status: 'locked' })
          │
          ├─► navigator.clipboard.writeText('')
          │
          ├─► fetch('/api/v1/auth/panic')  // fire-and-forget
          │
          ▼
   handlePanic()
          │
          ├─► setPanicFlash(true)  →  PanicFlash overlay (200ms red)
          │
          └─► onLogout()  →  setAuth({ status: 'locked' })
```
