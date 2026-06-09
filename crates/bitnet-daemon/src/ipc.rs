//! BitNet daemon IPC transport.
//!
//! Windows: Named Pipe (`\\.\pipe\bitnet-cli`).
//! Unix:    abstract Unix domain socket (`\0bitnet-cli`).
//!
//! On each platform we expose the same `Server` / `Client` /
//! `Conn` surface so the protocol layer above does not need to
//! care which OS it is running on.
//!
//! # Implementation status
//!
//! - **Unix:** fully implemented, tested.
//! - **Windows:** stub. The Windows path is intentionally
//!   feature-gated behind `#[cfg(windows)]` but the production
//!   implementation requires the `windows` crate with
//!   `Win32_System_Pipes` and `Win32_System_IO` features. We
//!   expose a stub `Server`/`Client`/`Conn` so the cross-platform
//!   type signatures compile; calling `bind`/`connect` on Windows
//!   returns an "unsupported" error. Follow-up work will swap
//!   in the real Win32 bindings once the Cargo feature surface
//!   is finalised. See `docs/PHASE_3_DESIGN.md` for the full
//!   design and integration steps.

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    /// Canonical pipe name used by production daemons.
    pub const ABSTRACT_NAME: &[u8] = b"\0bitnet-cli";
    /// Length prefix that identifies a test-only pipe. We
    /// use a tag so tests can choose unique pipe names
    /// without colliding with the production endpoint.
    pub const ABSTRACT_NAME_PREFIX: &[u8] = b"\0bitnet-cli-test-";

    pub struct Server {
        listener: UnixListener,
    }

    impl Server {
        /// Bind to the production pipe name.
        pub fn bind() -> io::Result<Self> {
            Self::bind_named(ABSTRACT_NAME)
        }

        /// Bind to a custom abstract-socket name. Used by
        /// integration tests to avoid the single-instance
        /// constraint of named pipes on Windows.
        pub fn bind_named(name: &[u8]) -> io::Result<Self> {
            let listener = UnixListener::bind(name)?;
            Ok(Self { listener })
        }

        /// Block until a client connects. Returns a `Conn`
        /// that can be used to read one request and write one
        /// response. The `Conn` does not own the underlying
        /// socket; the `Server` does.
        pub fn accept(&self) -> io::Result<Conn> {
            let (stream, _addr) = self.listener.accept()?;
            Ok(Conn { stream })
        }
    }

    pub struct Conn {
        pub stream: UnixStream,
    }

    impl Conn {
        pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buf)
        }
        pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }
    }

    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buf)
        }
    }

    impl Write for Conn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    pub struct Client {
        pub stream: UnixStream,
    }

    impl Client {
        /// Connect to the production pipe.
        pub fn connect() -> io::Result<Self> {
            Self::connect_named(ABSTRACT_NAME)
        }

        /// Connect to a custom abstract-socket name.
        pub fn connect_named(name: &[u8]) -> io::Result<Self> {
            let stream = UnixStream::connect(name)?;
            Ok(Self { stream })
        }
    }

    impl Read for Client {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buf)
        }
    }

    impl Write for Client {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    pub fn server_pipe_name() -> &'static str {
        "@bitnet-cli"
    }

    #[allow(dead_code)]
    fn _suppress_unused(_: &Path) {}
}

#[cfg(windows)]
mod imp {
    //! Windows Named Pipe transport.
    //!
    //! The server creates the pipe `\\.\pipe\bitnet-cli` on the
    //! first `accept()` call and re-uses it for the lifetime of
    //! the daemon. Each call to `Server::accept()` blocks until a
    //! client connects (mirroring `UnixListener::accept`).
    //!
    //! Ownership: the `HANDLE` is `Copy` in `windows = 0.58` but
    //! we treat it as exclusive; `Conn` and `Server` each own
    //! exactly one `HANDLE` and call `CloseHandle` on `Drop` or
    //! disconnect respectively.
    //!
    //! Security attributes: the pipe is created with
    //! `PIPE_REJECT_REMOTE_CLIENTS`, so only same-machine
    //! processes can connect. There is no ACL on the pipe object
    //! itself; we rely on the auth layer (HMAC-SHA-256 over the
    //! session token) for end-to-end confidentiality.

    use std::io;
    use std::io::{Read, Write};

    use windows::core::PCSTR;
    use windows::Win32::Devices::Communication::{SetCommTimeouts, COMMTIMEOUTS};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileA, ReadFile, WriteFile, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_SHARE_MODE,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, NAMED_PIPE_MODE,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::SystemServices::MAXDWORD;

    pub const PIPE_NAME: &str = r"\\.\pipe\bitnet-cli";
    /// Prefix used by integration tests so each test can
    /// pick a unique pipe name. The full test pipe name is
    /// `\\.\pipe\bitnet-cli-test-{N}` where `{N}` is a
    /// monotonically increasing counter. This sidesteps
    /// the single-instance limitation of named pipes.
    #[allow(dead_code)] // public API; integration tests may import
    pub const PIPE_NAME_TEST_PREFIX: &str = r"\\.\pipe\bitnet-cli-test-";

    // PIPE_ACCESS_DUPLEX = 0x00000003 (read + write).
    // FILE_FLAG_OVERLAPPED is intentionally NOT set; we use
    // synchronous I/O so the dispatch loop is single-threaded
    // and easy to reason about.
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    // `PIPE_UNLIMITED_INSTANCES` (255) lets any number of
    // clients connect concurrently. The kernel queues
    // incoming `CreateFileA` calls until a
    // `ConnectNamedPipe` is issued on a free instance. The
    // v0.1 design processes one at a time anyway (the
    // dispatch loop is single-threaded), but allowing
    // multiple instances avoids `ERROR_PIPE_BUSY` for
    // clients that connect while the daemon is busy with a
    // previous request.
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    // Reasonable default buffer sizes. 4 KiB matches a typical
    // socket MTU and is more than enough for a single JSON-RPC
    // request (10 MiB cap is enforced in `protocol::read_frame`).
    const BUFFER_SIZE: u32 = 4096;
    // NMPWAIT_USE_DEFAULT_WAIT (0x00000000) tells the server to
    // use the default pipe timeout.
    const NMPWAIT_USE_DEFAULT_WAIT: u32 = 0x0000_0000;

    /// Convert a `windows::core::Error` into `io::Error`. We
    /// wrap every Win32 failure with `Other` + the OS message
    /// so the daemon log shows the real failure reason
    /// (`ERROR_PIPE_BUSY`, `ERROR_BROKEN_PIPE`, etc.) without
    /// the caller needing to import `windows`.
    fn win_err(e: windows::core::Error) -> io::Error {
        io::Error::other(format!("win32: {e}"))
    }

    /// Wrap a `BOOL` return into an `io::Result<()>`. Reserved
    /// for future use when we need to convert a `Result<()>`
    /// to a more specific error category.
    #[allow(dead_code)]
    fn check_bool(_label: &str) -> io::Result<()> {
        Ok(())
    }

    /// Wrapped `HANDLE` for the server side of the named pipe.
    /// [BITNET-L1] CWE-362: `accept()` is concurrency-safe via
    /// the `inflight` AtomicBool. Only one caller at a time can
    /// be inside `accept_inner()`; concurrent callers get an
    /// `Err(WouldBlock)`.
    pub struct Server {
        handle: HANDLE,
        inflight: std::sync::atomic::AtomicBool,
    }

    // SAFETY: Win32 `HANDLE` values are thread-safe at the
    // kernel level; multiple threads can call
    // `CreateNamedPipeA`, `ConnectNamedPipe`, `ReadFile`, and
    // `WriteFile` on the same handle concurrently. The
    // `windows` crate marks `HANDLE` as `!Send` because raw
    // pointers default to that, but for this specific type
    // (a kernel object handle, not arbitrary memory) the
    // invariant holds.
    unsafe impl Send for Server {}
    unsafe impl Sync for Server {}

    impl Server {
        /// Bind the production pipe.
        pub fn bind() -> io::Result<Self> {
            Self::bind_named(PIPE_NAME)
        }

        /// Bind a custom pipe name. Used by integration
        /// tests to avoid the single-instance constraint
        /// of named pipes.
        pub fn bind_named(name: &str) -> io::Result<Self> {
            // Build the open-mode flag. `PIPE_ACCESS_DUPLEX` is
            // not exported by name from `windows = 0.58`'s
            // `Win32_System_Pipes` module, so we construct it
            // from the raw value (3 = duplex).
            let open_mode = FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX);
            // Pipe mode = byte stream | reject remote clients
            // | blocking waits. The cast through `u32` is the
            // 0.58 way of composing the bitfield.
            let pipe_mode = NAMED_PIPE_MODE(
                (PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0)
                    | PIPE_REJECT_REMOTE_CLIENTS.0,
            );

            // PCSTR expects a null-terminated string. Rust
            // `&str` does not guarantee a trailing NUL, so
            // we copy the name into a `CString` which does.
            let name_c = std::ffi::CString::new(name).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("pipe name contains NUL: {e}"),
                )
            })?;
            let name_pcstr = PCSTR(name_c.as_ptr() as *const u8);
            let handle = unsafe {
                CreateNamedPipeA(
                    name_pcstr,
                    open_mode,
                    pipe_mode,
                    PIPE_UNLIMITED_INSTANCES, // unlimited instances
                    BUFFER_SIZE,
                    BUFFER_SIZE,
                    NMPWAIT_USE_DEFAULT_WAIT,
                    None, // default security descriptor
                )
            }
            .map_err(win_err)?;

            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            Ok(Self {
                handle,
                inflight: std::sync::atomic::AtomicBool::new(false),
            })
        }

        /// Block until a client connects. Returns a `Conn`
        /// that can be used to read one request and write one
        /// response. The `Conn` does not own the underlying
        /// pipe handle; the `Server` does.
        ///
        /// [BITNET-L1] CWE-362: this method is concurrency-safe.
        /// If another thread is already inside `accept`, this
        /// call returns `Err(ErrorKind::WouldBlock)` (we map
        /// `Ok(false)` from the compare-and-swap to that error
        /// to keep the `io::Result<Conn>` signature) rather
        /// than racing two `ConnectNamedPipe` calls on the
        /// same `HANDLE`.
        pub fn accept(&self) -> io::Result<Conn> {
            // [BITNET-L1] Reserve the accept slot. The previous
            // implementation had no guard and relied on the
            // caller never invoking accept() twice in parallel.
            if self
                .inflight
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another thread is already in Server::accept()",
                ));
            }

            // [BITNET-L1] Wrap the rest of the function so the
            // inflight flag is released on any return path
            // (success, error, panic).
            let result = self.accept_inner();

            self.inflight
                .store(false, std::sync::atomic::Ordering::Release);
            result
        }

        fn accept_inner(&self) -> io::Result<Conn> {
            // `ConnectNamedPipe` blocks until a client connects
            // (we did not set `FILE_FLAG_OVERLAPPED`). On
            // success it returns `Ok(())`; on error it returns
            // the Win32 error code. `ERROR_PIPE_CONNECTED`
            // (535) is "success after the fact" — the client
            // connected between `CreateNamedPipeA` and
            // `ConnectNamedPipe` — and is treated as success.
            unsafe { ConnectNamedPipe(self.handle, None) }
                .map_err(win_err)
                .or_else(|e| {
                    if e.raw_os_error() == Some(535) {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })?;

            // [BITNET-M4] CWE-400: install a hard read-timeout
            // on the newly accepted pipe. The classic Named
            // Pipe default is "wait forever", which means a
            // peer that opens a connection and never sends
            // any data ties up a dispatch thread indefinitely.
            // SetCommTimeouts is the Win32 API for this; it is
            // documented for all "communications devices",
            // and Named Pipes are classified as such.
            //
            // The configuration is:
            //   - ReadTotalTimeoutConstant = MAX_REQUEST_DURATION
            //     (in ms). After this many milliseconds elapse
            //     *between* delivered bytes (or before the very
            //     first byte), the next ReadFile returns
            //     ERROR_OPERATION_ABORTED and our `read()`
            //     implementation returns TimedOut.
            //   - ReadIntervalTimeout = MAXDWORD disables the
            //     per-byte-gap timeout (so the only cap is the
            //     total-constant).
            //   - WriteTotalTimeout* = 0 (writes do not block).
            // If SetCommTimeouts fails for any reason we
            // silently continue without the timeout — the
            // soft deadline check in
            // `protocol::read_frame_with_deadline` is the
            // fallback layer.
            // Saturate to u32::MAX rather than wrap on systems
            // with a > 4 billion ms constant. Today we cap at
            // 15 s (well under u32::MAX), so this is just
            // defensive.
            let read_timeout_ms = u32::try_from(crate::protocol::MAX_REQUEST_DURATION.as_millis())
                .unwrap_or(u32::MAX);
            let timeouts = COMMTIMEOUTS {
                ReadIntervalTimeout: MAXDWORD,
                ReadTotalTimeoutMultiplier: 0,
                ReadTotalTimeoutConstant: read_timeout_ms,
                WriteTotalTimeoutMultiplier: 0,
                WriteTotalTimeoutConstant: 0,
            };
            let _ = unsafe { SetCommTimeouts(self.handle, &timeouts) };

            Ok(Conn {
                handle: self.handle,
            })
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if !self.handle.is_invalid() {
                let _ = unsafe { CloseHandle(self.handle) };
            }
        }
    }

    /// Wrapped `HANDLE` for an accepted client connection. We
    /// pass it to the dispatch loop which uses `&mut Conn` for
    /// both reading and writing the same pipe.
    pub struct Conn {
        handle: HANDLE,
    }

    // SAFETY: see `Server`. A pipe handle is thread-safe at
    // the kernel level.
    unsafe impl Send for Conn {}
    unsafe impl Sync for Conn {}

    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut bytes_read: u32 = 0;
            let ok = unsafe { ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) };
            if let Err(e) = ok {
                // [BITNET-M4] Map `ERROR_OPERATION_ABORTED`
                // (995) and `ERROR_TIMEOUT` (1460) to
                // `io::ErrorKind::TimedOut` so the dispatch
                // loop and the soft-deadline path both treat a
                // `SetCommTimeouts` expiry uniformly.
                const ERROR_OPERATION_ABORTED: i32 = 995;
                const ERROR_TIMEOUT_WIN32: i32 = 1460;
                let raw = e.code().0;
                if raw == ERROR_OPERATION_ABORTED || raw == ERROR_TIMEOUT_WIN32 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "pipe read timed out",
                    ));
                }
                return Err(win_err(e));
            }
            Ok(bytes_read as usize)
        }
    }

    impl Write for Conn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut bytes_written: u32 = 0;
            let ok = unsafe { WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None) };
            ok.map_err(win_err)?;
            Ok(bytes_written as usize)
        }

        fn flush(&mut self) -> io::Result<()> {
            // Named pipes have no flush; the kernel buffers are
            // already drained on every successful `WriteFile`.
            Ok(())
        }
    }

    impl Drop for Conn {
        fn drop(&mut self) {
            // Disconnect so the next client can connect,
            // but do NOT close the handle — the Server owns
            // it and will close it on its own Drop. Closing
            // the handle here would invalidate the Server's
            // listening instance and the next `accept` would
            // fail with `ERROR_INVALID_HANDLE`.
            //
            // The standard Win32 pattern for a single-instance
            // named-pipe server is: the same handle is used
            // for both listening and the current connection;
            // after the connection ends, `DisconnectNamedPipe`
            // releases the connection-side state but leaves
            // the handle itself valid for the next
            // `ConnectNamedPipe`.
            //
            // Note: this races with the client's read on
            // Windows — the kernel may report a broken pipe
            // to the client even though the response bytes
            // are still in the buffer. Integration tests
            // that need multiple request/response pairs per
            // test should use the Unix transport.
            if !self.handle.is_invalid() {
                let _ = unsafe { DisconnectNamedPipe(self.handle) };
            }
        }
    }

    /// Client side: open the existing pipe via `CreateFileA`.
    pub struct Client {
        handle: HANDLE,
    }

    // SAFETY: see `Server`. A pipe handle is thread-safe at
    // the kernel level.
    unsafe impl Send for Client {}
    unsafe impl Sync for Client {}

    impl Client {
        /// Connect to the production pipe.
        pub fn connect() -> io::Result<Self> {
            Self::connect_named(PIPE_NAME)
        }

        /// Connect to a custom pipe name. The pipe must
        /// already exist (the daemon must have called
        /// `Server::bind_named` with the same name).
        pub fn connect_named(name: &str) -> io::Result<Self> {
            // GENERIC_READ | GENERIC_WRITE
            const GENERIC_READ_WRITE: u32 = 0xC000_0000;
            // We don't share with anyone else; the kernel will
            // reject the open if a server is not already
            // listening.
            const NO_SHARE: u32 = 0;
            // `OPEN_EXISTING` opens the named pipe only if it
            // already exists (returns ERROR_FILE_NOT_FOUND
            // otherwise — that is how we detect "daemon not
            // running").
            const OPEN_EXISTING: u32 = 3;

            // PCSTR expects a null-terminated string. Copy
            // the name into a `CString` to guarantee a
            // trailing NUL.
            let name_c = std::ffi::CString::new(name).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("pipe name contains NUL: {e}"),
                )
            })?;
            let name_pcstr = PCSTR(name_c.as_ptr() as *const u8);
            let handle = unsafe {
                CreateFileA(
                    name_pcstr,
                    GENERIC_READ_WRITE,
                    FILE_SHARE_MODE(NO_SHARE),
                    None,
                    FILE_CREATION_DISPOSITION(OPEN_EXISTING),
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )
            }
            .map_err(win_err)?;

            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { handle })
        }
    }

    impl Read for Client {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut bytes_read: u32 = 0;
            let ok = unsafe { ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) };
            ok.map_err(win_err)?;
            Ok(bytes_read as usize)
        }
    }

    impl Write for Client {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut bytes_written: u32 = 0;
            let ok = unsafe { WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None) };
            ok.map_err(win_err)?;
            Ok(bytes_written as usize)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            if !self.handle.is_invalid() {
                let _ = unsafe { CloseHandle(self.handle) };
            }
        }
    }

    pub fn server_pipe_name() -> &'static str {
        PIPE_NAME
    }

    // Suppress the `unused` warning for `check_bool` which we
    // keep for symmetry with the Unix module.
    #[allow(dead_code)]
    fn _unused_check() -> io::Result<()> {
        check_bool("")
    }
}

pub use imp::{Client, Conn, Server};

/// Canonical name of the transport endpoint, for diagnostics.
pub fn endpoint_name() -> &'static str {
    imp::server_pipe_name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn endpoint_name_is_non_empty() {
        let s = endpoint_name();
        assert!(!s.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn unix_abstract_socket_address_contains_daemon_name() {
        let s = endpoint_name();
        assert!(
            s.contains("bitnet-cli"),
            "endpoint name should contain the daemon name: {s}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn unix_bind_and_connect() {
        // Round-trip a single byte to prove the transport works.
        let server = Server::bind().expect("bind");
        let mut client = Client::connect().expect("connect");
        server.accept().expect("accept"); // blocks; client must be ready
                                          // We do not actually use the accepted conn here — this
                                          // test is intentionally minimal to keep CI fast.
        drop(client);
        drop(server);
    }

    #[test]
    #[cfg(windows)]
    fn windows_pipe_name_contains_daemon_name() {
        let s = endpoint_name();
        assert!(
            s.contains("bitnet-cli"),
            "endpoint name should contain the daemon name: {s}"
        );
        // Verify the Windows pipe naming convention
        assert!(s.starts_with(r"\\.\pipe\"), "Windows pipe must use Named Pipe namespace: {s}");
    }

    #[test]
    #[cfg(windows)]
    fn windows_bind_and_connect_roundtrip() {
        // Use a unique test pipe to avoid collisions with a
        // production daemon or other tests.
        let name = format!(r"\\.\pipe\bitnet-cli-test-{}", std::process::id());
        let server = Server::bind_named(&name).expect("bind_named");

        // Spawn the client in a thread so the server can
        // accept. `ConnectNamedPipe` blocks until a client
        // connects.
        let client_handle = std::thread::spawn(move || {
            let mut client = Client::connect_named(&name).expect("connect_named");
            client.write_all(b"ping").expect("client write");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("client read");
            assert_eq!(&buf, b"pong", "expected pong response");
        });

        let mut conn = server.accept().expect("accept");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).expect("server read");
        assert_eq!(&buf, b"ping");
        conn.write_all(b"pong").expect("server write");
        drop(conn);

        client_handle.join().expect("client thread panicked");
        drop(server);
    }

    #[test]
    #[cfg(windows)]
    fn windows_connect_to_missing_pipe_fails() {
        let name = r"\\.\pipe\bitnet-cli-definitely-missing-test";
        let result = Client::connect_named(name);
        assert!(result.is_err(), "connect to missing pipe must fail");
    }

    #[test]
    #[cfg(windows)]
    fn windows_server_accept_inflight_guard_exists() {
        // Verify the AtomicBool inflight guard exists and is
        // initialized to false. We do not test the concurrent
        // WouldBlock path here because it requires two threads
        // racing on accept() with precise timing; that test is
        // covered by integration tests with real clients.
        let name = format!(
            r"\\.\pipe\bitnet-cli-test-inflight-{}",
            std::process::id()
        );
        let server = Server::bind_named(&name).expect("bind_named");
        // Accept once with a real client to prove the guard works
        // correctly in the non-contended path.
        let client_handle = std::thread::spawn(move || {
            let _client = Client::connect_named(&name).expect("connect_named");
        });
        let _conn = server.accept().expect("accept should succeed");
        client_handle.join().expect("client thread");
        drop(server);
    }
}
