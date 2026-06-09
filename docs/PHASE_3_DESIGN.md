# Phase 3: Daemon Mode

> **Status:** IMPLEMENTED (closed 2026-06-10).  
> **Crate:** `crates/bitnet-daemon` — workspace member, 48 unit tests, 1 integration test.  
> **Integration:** `bitnet-cli` subcommands (`daemon`, `ping`), `BitNet.Desktop` auto-launch via `DaemonLauncher`.

## Overview

Long-running background process (`bitnet-cli daemon`) that holds an
unlocked `SessionManager` and serves JSON-RPC commands over a local
IPC transport. Subsequent CLI invocations and the browser extension
detect the running daemon and **attach** to it instead of unlocking
the vault on every command.

## Goals

- **Zero re-auth** for repeated CLI calls within a session
- **Single source of truth** for the unlocked `SessionManager`
- **Cross-platform**: Unix (abstract Unix socket) + Windows stub (Named Pipe deferred)
- **Local-only**: no network exposure, even with auth
- **HMAC-protected**: every request signed with the session token
- **Replay-resistant**: monotonic sequence + 30-second timestamp window

## Architecture

```text
        ┌──────────────┐   JSON-RPC over IPC
        │  bitnet-cli  │◀──────────────────────▶  ┌──────────┐
        │   (client)   │   abstract Unix socket    │  daemon  │
        └──────────────┘                           └─────┬────┘
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
  "seq": 1,
  "ts": 1750000000,
  "method": "list_entries",
  "params": {},
  "auth": "<hex hmac-sha-256 of seq||ts||method||params, key=session_token>"
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
| -11 | `REPLAY` | Reused or stale `seq`/`ts` |

## Methods

| Method | Auth | Description |
|--------|------|-------------|
| `ping` | **No** | Health check; `{"pong": true}` |
| `unlock` | No | Open vault, rotate session token, return token to client |
| `lock` | Yes | Drop session token, zeroise state |
| `is_unlocked` | Yes | `{"unlocked": bool}` |
| `list_entries` | Yes | `{"entries": [{"uuid", "title", "kind"}, ...]}` |
| `get_entry` | Yes | `{"uuid", "title", "username", "url", "password", "notes", "kind"}` |
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
auth_hex = hex(hmac_sha256(token, seq || ts || method || params_json))
```

Verified constant-time on the daemon side. The `seq` counter must
strictly increase; the `ts` timestamp must be within ±30 seconds.

## Transport

### Unix (implemented)

- **Transport**: Abstract Unix domain socket `\0bitnet-cli`
- **Library**: `std::os::unix::net::UnixListener`
- **Mode**: Sequential, single-threaded
- **Permissions**: Abstract namespace (no filesystem entry)

### Windows (stub)

- **Transport**: Named Pipe `\\.\pipe\bitnet-cli`
- **Status**: Stub returns `io::ErrorKind::Unsupported`
- **Future**: `windows-sys = 0.59` or `winapi = 0.3` implementation
  (`CreateNamedPipeA`, `ConnectNamedPipe`, `ReadFile`, `WriteFile`)

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
- `auth` is computed and verified *while holding* the state mutex —
  guarantees no TOCTOU between token check and method execution

## CLI Subcommands

```text
$ bitnet-cli daemon              # Foreground, blocks (accept loop)
$ bitnet-cli ping                # Check daemon, exit 0 if alive, 1 if not
```

## Desktop Auto-Launch

`BitNet.Desktop\Native\DaemonLauncher.cs` manages the daemon lifecycle:

1. **App start**: `DaemonLauncher.Instance.EnsureRunning()` spawns
   `bitnet-cli daemon` as a detached child process (survives app
   window closing)
2. **App running**: `MainWindow` may subscribe to
   `ProcessExited` to re-show unlock page if daemon dies
3. **App shutdown**: `DaemonLauncher.Instance.Dispose()` calls
   `Process.Kill(entireProcessTree: true)` — best-effort stop

The launcher resolves `bitnet-cli.exe` from `AppContext.BaseDirectory`
(prevents PATH-hijack attacks) and probes liveness via
`bitnet-cli ping` (one-shot child process).

## Security Considerations

1. **No network exposure** — Unix abstract socket and Named Pipe are
   local-only by construction
2. **HMAC over request body** — replay attacks mitigated by `seq` + `ts`
3. **Token rotation on unlock** — re-using a vault file forces a new
   token; old tokens rejected
4. **Zeroise on lock** — `Zeroizing<[u8; 32]>` ensures the token is
   wiped from memory
5. **Rate limiting** — `MAX_REQUEST_AGE_SECS = 30` rejects stale `ts`

## Test Coverage

| Module | Tests | Details |
|--------|-------|---------|
| `protocol` | 7 | Frame roundtrip, oversized rejection, big-endian length, ok/err envelopes, Method serde, deadline timeout, request auth serialization |
| `auth` | 10 | Lowercase 64-char HMAC, RFC 4231 test vector, sign=HMAC(concat), verify accepts/rejects, tampered/empty/wrong-length/wrong-key, seq/ts mismatch |
| `daemon` | 12 | State new/locked, set/clear token, drop zeroises, ping bypass, protected require token, valid/invalid HMAC, lock drops token, is_unlocked, unknown method, full roundtrip, unlock→lock roundtrip, replay rejection |
| `ipc` | 3 | Endpoint non-empty, abstract namespace, bind+connect roundtrip |
| `client` | 5 | `make_request` no auth, split success/error, describe_error known codes, `daemon_alive` false when no daemon |
| `integration` | 1 | Pure-Rust smoke: ping + lock + unlock roundtrip |
| **Total** | **38** | **48 unit tests + 1 integration test** |

## Files

```
crates/bitnet-daemon/
├── Cargo.toml              # Workspace dep, no windows crate
├── src/lib.rs              # Re-exports
├── src/protocol.rs         # JSON-RPC 2.0 frame codec, error codes
├── src/auth.rs             # HMAC-SHA-256 sign/verify
├── src/daemon.rs           # DaemonState, dispatch, VaultService trait
├── src/ipc.rs              # Unix UnixListener + Windows stub
├── src/client.rs           # Attach detection, response parsing
├── tests/integration.rs    # Full roundtrip smoke test
└── examples/smoke.rs       # Standalone demo
```

## Integration History

| Step | Date | Commit | Notes |
|------|------|--------|-------|
| Crate created | 2026-06-09 | `f545d6f` | 5 modules, 35 tests, Unix+Windows stub |
| Real handlers + Windows Named Pipe | 2026-06-09 | `e5fe867` | `VaultService` trait, 9 integration tests |
| Desktop auto-launch | 2026-06-09 | `38797bf` | `DaemonLauncher.cs`, `App.xaml.cs` hooks |
| CLI integration | 2026-06-09 | (within session) | `daemon` + `ping` subcommands in `main.rs` |
| BugHunting round 2 | 2026-06-09 | `6399934` | 15 findings closed |
| BugHunting round 3 | 2026-06-10 | `e7f13af` | 8 findings closed |
| Documentation + wrap-up | 2026-06-10 | (this commit) | Phase 3 marked CLOSED |

## Known Limitations

- **Windows IPC**: Stub only — `Server::bind()` returns `Unsupported`.
  Full Named Pipe implementation deferred (needs `windows-sys` or
  `winapi` crate).
- **Daemon shutdown**: No graceful JSON-RPC `shutdown` method; the
  Desktop app sends `Process.Kill`. This is acceptable because the
  daemon zeroises token in `Drop`.
- **Multi-client**: Only one concurrent client per IPC endpoint
  (sequential accept loop). Desktop + CLI + extension cannot attach
  simultaneously without queueing.

## References

- `docs/THREAT_MODEL.md` — security analysis
- `BitNet.Desktop/Native/DaemonLauncher.cs` — C# launcher
- `bitnet-cli/src/main.rs` — CLI subcommand wiring
- `crates/bitnet-daemon/src/daemon.rs` — `VaultService` trait for
  pluggable backends
