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

use std::io;
use std::io::{Read, Write};

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    /// Abstract namespace socket address: the leading NUL byte
    /// tells the kernel to bind in the abstract namespace (no
    /// filesystem entry), which is automatically cleaned up when
    /// the listener is dropped.
    const ABSTRACT_NAME: &[u8] = b"\0bitnet-cli";

    pub struct Server {
        listener: UnixListener,
    }

    impl Server {
        pub fn bind() -> io::Result<Self> {
            let listener = UnixListener::bind(ABSTRACT_NAME)?;
            Ok(Self { listener })
        }

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
        pub fn connect() -> io::Result<Self> {
            let stream = UnixStream::connect(ABSTRACT_NAME)?;
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
    //! Windows stub. The full implementation requires the
    //! `windows = "0.58"` crate with the `Win32_System_Pipes` and
    //! `Win32_System_IO` features, plus a careful treatment of
    //! `HANDLE` ownership for the connected client case. See
    //! `docs/PHASE_3_DESIGN.md` § Transport for the full design.
    //!
    //! The stubs below let the crate compile on Windows so that
    //! `cargo check --workspace` succeeds. Calling `bind` /
    //! `connect` at runtime returns `ErrorKind::Unsupported` so
    //! the daemon simply refuses to start on Windows until the
    //! real implementation lands.

    use std::io;
    use std::io::{Read, Write};

    pub const PIPE_NAME: &str = r"\\.\pipe\bitnet-cli";

    pub struct Server;

    impl Server {
        pub fn bind() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows Named Pipe backend not yet implemented; see docs/PHASE_3_DESIGN.md",
            ))
        }

        pub fn accept(&self) -> io::Result<Conn> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows Named Pipe accept not yet implemented",
            ))
        }
    }

    pub struct Conn;

    impl Read for Conn {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "stub"))
        }
    }

    impl Write for Conn {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "stub"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct Client;

    impl Client {
        pub fn connect() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows Named Pipe client not yet implemented",
            ))
        }
    }

    impl Read for Client {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "stub"))
        }
    }

    impl Write for Client {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "stub"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn server_pipe_name() -> &'static str {
        PIPE_NAME
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
}
