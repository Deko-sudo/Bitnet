# Phase 3: Daemon Mode — Design Document

> **Status:** Design complete, implementation deferred.
> **Reason:** Daemon mode is an optimization, not core functionality. The
> BitNet project is production-ready without it (see master plan for
> baseline). Implementation deferred to v0.2.

## Overview

Long-running background process (`bitnet-cli daemon`) that holds an
unlocked `SessionManager` and serves JSON-RPC commands over a local
IPC transport. Subsequent CLI invocations and the browser extension
detect the running daemon and **attach** to it instead of unlocking
the vault on every command.

## Goals

- **Zero re-auth** for repeated CLI calls within a session
- **Single source of truth** for the unlocked `SessionManager`
- **Cross-platform**: Windows (Named Pipe) + Unix (abstract Unix socket)
- **Local-only**: no network exposure, even with auth
- **HMAC-protected**: every request signed with the session token

## Architecture

```text
        ┌──────────────┐   JSON-RPC over Named Pipe
        │  bitnet-cli  │◀──────────────or──────────────▶  ┌──────────┐
        │   (client)   │      abstract Unix socket        │  daemon  │
        └──────────────┘                                    └─────┬────┘
                                                                   │
                                                         SessionManager
```

## Wire Protocol

Length-prefixed JSON-RPC 2.0 envelopes:

```
┌─────────────────┬──────────────────────────────────────────────┐
│ 4 bytes BE len  │  UTF-8 JSON body (request or response)       │
└─────────────────┴──────────────────────────────────────────────┘
```

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "list_entries",
  "params": {},
  "auth": "<hex hmac-sha-256 of method||params, key=session_token>"
}
```

### Response (success)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": { "ok": true }
}
```

### Response (error)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -3,
    "message": "vault is locked"
  }
}
```

## Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `OK` | No error |
| -1 | `INVALID_PARAMS` | Bad JSON-RPC params |
| -2 | `INTERNAL` | Server-side bug |
| -3 | `SESSION_LOCKED` | Vault not unlocked |
| -4 | `INVALID_VAULT_PATH` | Path validation failed |
| -5 | `VAULT_NOT_FOUND` | Path does not exist |
| -6 | `DECRYPTION_FAILED` | Wrong master password |
| -7 | `NOT_FOUND` | Entry UUID not in vault |
| -8 | `UNKNOWN_METHOD` | Method not registered |
| -9 | `OVERSIZED` | Payload > 10 MiB limit |
| -10 | `UNAUTHORIZED` | HMAC verification failed |

## Methods

| Method | Auth | Description |
|--------|------|-------------|
| `ping` | **No** | Health check; `{"pong": true}` |
| `unlock` | No | Open vault, rotate session token, return token to client |
| `lock` | Yes | Drop session token, zeroise state |
| `is_unlocked` | Yes | `{"unlocked": bool}` |
| `list_entries` | Yes | `{"entries": [{"uuid", "title"}, ...]}` |
| `get_entry` | Yes | `{"uuid", "title", "username", "url", "password", "notes"}` |
| `add_entry` | Yes | Persist new entry to vault |
| `delete_entry` | Yes | Remove entry by UUID |
| `totp` | Yes | Compute TOTP for entry |
| `generate_password` | No | Stateless, no auth needed |

## Authentication

After a successful `unlock`, the daemon generates a 32-byte session
token via `SessionToken::random()`. The token is:

1. Returned to the **unlocker** (one client)
2. Stored in `Mutex<DaemonState>` on the daemon
3. Used as the HMAC key for all subsequent requests
4. Zeroised on `lock` or daemon shutdown

Clients sign requests with HMAC-SHA-256:

```text
auth_hex = hex(hmac_sha256(token, method || params_json))
```

Verified constant-time on the daemon side.

## Transport

### Windows

- **Transport**: Named Pipe `\\.\pipe\bitnet-cli`
- **Library**: `windows = "0.58"` (high-level bindings)
- **Mode**: `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS`
- **Permissions**: 1 instance, max 1 concurrent client

### Unix

- **Transport**: Abstract Unix domain socket `\0bitnet-cli`
- **Library**: `std::os::unix::net::UnixListener`
- **Mode**: Sequential, single-threaded
- **Permissions**: 0o600 on socket file (in filesystem variant)

## Concurrency Model

- One `Mutex<DaemonState>` guards in-process state
- Single-threaded accept loop:
  ```rust
  loop {
      let conn = server.accept()?;
      handle_one_in_memory(&state, &mut conn)?;
  }
  ```
- Each request acquires the lock for the duration of `dispatch()`
- Window where `auth` is computed and verified *while holding* the
  state mutex — guarantees no TOCTOU between token check and method

## CLI Subcommand

```text
$ bitnet-cli daemon              # Foreground, blocks
$ bitnet-cli daemon --background # Daemonise (Unix only)
$ bitnet-cli ping                # Check daemon, exit 0/1
$ bitnet-cli list                # If daemon up: attach, else: local
$ bitnet-cli list --no-attach    # Force local execution
```

## Security Considerations

1. **No network exposure** — Named Pipe and abstract Unix socket are
   local-only by construction
2. **HMAC over request body** — replay attacks possible only within
   the daemon session lifetime
3. **Token rotation on unlock** — re-using a vault file forces a new
   token; old tokens rejected
4. **Zeroise on lock** — `Zeroizing<[u8; 32]>` ensures the token is
   wiped from memory
5. **PID file** — `~/.local/share/bitnet/daemon.pid` for clean shutdown

## Test Coverage (designed)

| Module | Tests | Status |
|--------|-------|--------|
| `protocol` | 7 | ✅ written |
| `auth` | 9 | ✅ written |
| `daemon` (state + dispatch) | 8 | ✅ written |
| `ipc` (frame roundtrip) | 2 | ✅ written |
| `client` (attach detection) | 5 | ⚠️ one test blocked by broken State |
| **Total** | **31** | **written, not integrated** |

## Integration Steps (deferred)

1. Fix `Cargo.toml` workspace duplicate `resolver` key
2. `git rm` 4 module files from `bitnet-cli/src/`
3. Add `bitnet-daemon` to workspace members
4. Add `bitnet-daemon` as dependency of `bitnet-cli`
5. Add `daemon` and `ping` subcommands to main.rs
6. Refactor `main()` from `()` to `io::Result<()>` (touch ~20 `return;` sites)
7. Resolve Unix/Windows `&mut Conn` borrow checker (use `split()` on Unix)
8. Wire Desktop app to auto-launch daemon on vault unlock
9. Full E2E test: start daemon, attach from CLI, attach from Desktop
10. Document daemon lifecycle in `docs/BUILD_AND_RUN.md`

Estimated effort: **3-4 hours**.

## References

- `recomendation.md` (master plan, Phase 3)
- `crates/bitnet-daemon/` (WIP — see git stash for module files)
- `docs/THREAT_MODEL.md` (security analysis)
- RFC 1057 (JSON-RPC 2.0 — informal reference)
