use bitnet_core::{util, SessionManager};
use bitnet_crypto::PasswordGeneratorFlags;
use clap::{Parser, Subcommand};
use std::io::{self, BufRead, Write};
use tracing::{error, info};

/// [BITNET-M5] Centralized error logger. Logs the operation tag and an
/// opaque `kind` (so the operator can grep for specific failure modes)
/// but does **not** include the full `Display` chain in the structured
/// event — the chain may echo back user-supplied values such as file
/// paths. The user-facing message is still printed to stderr verbatim.
fn log_error(op: &'static str, _e: &dyn std::fmt::Display) {
    // `kind` is intentionally a constant in the structured event. We
    // deliberately do not include the error message in the structured
    // log because it can carry fragments of user input (e.g. the
    // file path the user pasted in an error like "vault not found at
    // <PATH>"). The terminal output (eprintln!) is the right place
    // for the human-readable cause.
    error!(op, kind = "Error", "operation failed");
}

/// Initialize structured logging. Honours `RUST_LOG` env var.
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .without_time()
        .try_init();
}

#[derive(Parser)]
#[command(name = "bitnet-cli")]
#[command(
    about = "BitNet Password Manager CLI\nWARNING: Passwords and TOTP codes are printed to stdout by default and may be retained in terminal scrollback."
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Suppress printing of passwords and TOTP codes to stdout"
    )]
    no_echo: bool,
    /// Start interactive REPL where the unlocked session persists between commands.
    #[arg(long, global = true)]
    repl: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a long-lived background daemon. Other bitnet-cli
    /// invocations and the browser extension can attach to it
    /// instead of unlocking the vault on every command.
    ///
    /// On Windows this is currently a stub (returns
    /// "unsupported") until the Win32 Named Pipe backend lands;
    /// see `docs/PHASE_3_DESIGN.md` for the full design.
    Daemon,
    /// Graceful shutdown of the running daemon. Sends a
    /// `shutdown` JSON-RPC request and waits for the daemon to
    /// exit. The daemon will finish any in-flight request,
    /// zeroise the token, and terminate cleanly.
    Stop,
    /// Ping the running daemon. Exits 0 if it is reachable, 1
    /// otherwise. Useful for shell scripts that need to know
    /// whether a daemon is up before running sensitive commands.
    Ping,
    /// Unlock a vault file
    Unlock {
        /// Path to vault file
        path: String,
    },
    /// Lock the current vault
    Lock,
    /// List all entries
    List,
    /// Get password for an entry
    Get {
        /// Entry UUID (hex)
        uuid: String,
    },
    /// Get TOTP code for an entry
    Totp {
        /// Entry UUID (hex)
        uuid: String,
    },
    /// Generate a random password
    Generate {
        /// Password length
        #[arg(short, long, default_value_t = 16)]
        length: usize,
        /// Include uppercase letters
        #[arg(long, default_value_t = true)]
        uppercase: bool,
        /// Include lowercase letters
        #[arg(long, default_value_t = true)]
        lowercase: bool,
        /// Include digits
        #[arg(long, default_value_t = true)]
        digits: bool,
        /// Include symbols
        #[arg(long, default_value_t = true)]
        symbols: bool,
        /// Exclude ambiguous characters
        #[arg(long, default_value_t = false)]
        ambiguous: bool,
    },
    /// Show vault file fingerprint (SHA-256)
    Info {
        /// Path to vault file
        path: String,
    },
    /// Change the master password of the currently unlocked vault
    ChangePassword {
        /// Path to vault file
        path: String,
    },
    /// Create a new vault
    Create {
        /// Path to new vault file
        path: String,
    },
}

fn main() {
    init_logging();
    let cli = Cli::parse();
    let no_echo = cli.no_echo;
    let manager = SessionManager::new();

    if cli.repl {
        run_repl(manager, no_echo);
        return;
    }

    match cli.command {
        Commands::Daemon => {
            // Long-running accept loop. We hold the state mutex
            // inside `handle_one_in_memory`; the loop itself runs
            // single-threaded which is sufficient for the v0.1
            // design (see docs/PHASE_3_DESIGN.md).
            let server = bitnet_daemon::Server::bind();
            let server = match server {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("daemon: failed to bind: {e}");
                    std::process::exit(1);
                }
            };
            let state = bitnet_daemon::DaemonState::new();
            let state = std::sync::Mutex::new(state);
            // The production service wires the daemon to a real
            // bitnet_core::SessionManager; for now we use a
            // NoopVaultService that allows `unlock` to succeed
            // (returning a deterministic test token) but rejects
            // every other method with UNKNOWN_METHOD. This is
            // the intended v0.1 wiring: the daemon is reachable
            // and the protocol is end-to-end correct, while
            // service-level handlers are filled in follow-up
            // commits.
            let service = bitnet_daemon::NoopVaultService;
            info!("bitnet-cli daemon listening");
            loop {
                // [BITNET-S1] Graceful shutdown check.
                {
                    let guard = state.lock().unwrap();
                    if guard.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                        info!("daemon shutting down gracefully");
                        break;
                    }
                }
                match server.accept() {
                    Ok(mut conn) => {
                        if let Err(_e) =
                            bitnet_daemon::handle_one_in_memory(&state, &service, &mut conn)
                        {
                            error!(op = "daemon", kind = "Error", "client dispatch failed");
                        }
                    }
                    Err(e) => {
                        error!(op = "daemon", kind = "Error", "accept failed");
                        tracing::debug!(error = %e, "accept failed");
                    }
                }
            }
        }
        Commands::Stop => {
            if !bitnet_daemon::daemon_alive() {
                eprintln!("daemon is not running");
                std::process::exit(1);
            }
            match bitnet_daemon::Client::connect() {
                Ok(mut client) => {
                    let req = bitnet_daemon::Request {
                        jsonrpc: "2.0".into(),
                        id: 1,
                        method: "shutdown".into(),
                        params: serde_json::json!({}),
                        auth: None,
                        seq: None,
                        ts: None,
                    };
                    let body = serde_json::to_value(&req).unwrap();
                    if let Err(e) = bitnet_daemon::protocol::write_frame(&mut client, &body) {
                        eprintln!("failed to send shutdown request: {e}");
                        std::process::exit(1);
                    }
                    let _ = bitnet_daemon::protocol::read_frame(&mut client);
                    println!("shutdown request sent");
                    // Poll briefly until the daemon pipe disappears.
                    let start = std::time::Instant::now();
                    while bitnet_daemon::daemon_alive() && start.elapsed().as_secs() < 5 {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    if bitnet_daemon::daemon_alive() {
                        eprintln!("daemon did not exit within 5s");
                        std::process::exit(1);
                    }
                    println!("daemon stopped");
                }
                Err(e) => {
                    eprintln!("failed to connect to daemon: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Ping => {
            if bitnet_daemon::daemon_alive() {
                println!("daemon alive");
            } else {
                eprintln!("daemon not reachable");
                std::process::exit(1);
            }
        }
        Commands::Unlock { path } => {
            if !util::validate_vault_path(&path) {
                eprintln!(
                    "Invalid vault path. Must be a .bitnet file without parent-dir traversal."
                );
                return;
            }
            // [BITNET-M5] CWE-755: avoid `unwrap()` so a
            // stdin-not-a-TTY error does not panic the CLI and
            // leak the master password string on the unwind.
            // On error, return early; the user can retry.
            let password = match rpassword::prompt_password("Master password: ") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read master password: {e}");
                    return;
                }
            };
            match manager.unlock(&path, password.as_bytes()) {
                Ok(()) => println!("Vault unlocked successfully."),
                Err(e) => eprintln!("Failed to unlock vault: {}", e),
            }
        }
        Commands::Lock => {
            manager.lock();
            info!("vault locked");
            println!("Vault locked.");
        }
        Commands::List => match manager.list_entries() {
            Ok(entries) => {
                for entry in entries {
                    let totp_indicator = if entry.has_totp { " [TOTP]" } else { "" };
                    println!(
                        "{} - {}{}",
                        hex_uuid(&entry.uuid),
                        entry.title.as_str(),
                        totp_indicator
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "list entries failed");
                eprintln!("Error: {}", e)
            }
        },
        Commands::Get { uuid } => {
            let uuid_bytes = match parse_hex_uuid(&uuid) {
                Some(u) => u,
                None => {
                    error!(uuid = %uuid, "invalid UUID format");
                    eprintln!("Invalid UUID format");
                    return;
                }
            };
            match manager.get_password(&uuid_bytes) {
                Ok(password) => {
                    if !no_echo {
                        println!("{}", password.as_str());
                    }
                }
                Err(e) => {
                    log_error("list entries", &e);
                    eprintln!("Error: {}", e)
                }
            }
        }
        Commands::Totp { uuid } => {
            let uuid_bytes = match parse_hex_uuid(&uuid) {
                Some(u) => u,
                None => {
                    error!(uuid = %uuid, "invalid UUID format");
                    eprintln!("Invalid UUID format");
                    return;
                }
            };
            match manager.get_totp(&uuid_bytes) {
                Ok(Some((code, remaining))) => {
                    if !no_echo {
                        println!("Code: {} (expires in {}s)", code, remaining);
                    }
                }
                Ok(None) => println!("No TOTP configured for this entry."),
                Err(e) => {
                    log_error("list entries", &e);
                    eprintln!("Error: {}", e)
                }
            }
        }
        Commands::Generate {
            length,
            uppercase,
            lowercase,
            digits,
            symbols,
            ambiguous,
        } => {
            let flags = PasswordGeneratorFlags {
                length,
                include_uppercase: uppercase,
                include_lowercase: lowercase,
                include_digits: digits,
                include_symbols: symbols,
                exclude_ambiguous: ambiguous,
            };
            let pwd = manager.generate_password(&flags);
            if !no_echo {
                println!("{}", pwd);
            }
        }
        Commands::Info { path } => {
            if !util::validate_vault_path(&path) {
                eprintln!(
                    "Invalid vault path. Must be a .bitnet file without parent-dir traversal."
                );
                return;
            }
            match std::fs::read(&path) {
                Ok(data) => {
                    let hash = bitnet_crypto::sha256(&data);
                    println!("Fingerprint (SHA-256): {}", util::hex_encode(&hash));
                }
                Err(e) => eprintln!("Failed to read file: {}", e),
            }
        }
        Commands::ChangePassword { path } => {
            if !util::validate_vault_path(&path) {
                eprintln!("Invalid vault path.");
                return;
            }
            // In CLI mode there is no persistent session, so we cannot
            // prove knowledge of the current master password from a stored
            // key. We re-prompt and rely on a one-shot unlock + change.
            // [BITNET-M5] CWE-755: avoid `unwrap()` so a
            // stdin-not-a-TTY error does not panic the CLI and
            // leak the master password string on the unwind.
            let old = match rpassword::prompt_password("Current master password: ") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read master password: {e}");
                    return;
                }
            };
            let new = match rpassword::prompt_password("New master password: ") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read master password: {e}");
                    return;
                }
            };
            let confirm = match rpassword::prompt_password("Confirm new master password: ") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read master password: {e}");
                    return;
                }
            };
            if new != confirm {
                eprintln!("New passwords do not match.");
                return;
            }
            if let Err(e) = manager.unlock(&path, old.as_bytes()) {
                eprintln!("Unlock failed: {}", e);
                return;
            }
            match manager.change_master_password(&path, old.as_bytes(), new.as_bytes()) {
                Ok(()) => println!("Master password changed."),
                Err(e) => eprintln!("Change failed: {}", e),
            }
        }
        Commands::Create { path } => {
            if !util::validate_vault_path(&path) {
                eprintln!(
                    "Invalid vault path. Must be a .bitnet file without parent-dir traversal."
                );
                return;
            }
            // [BITNET-M5] CWE-755: avoid `unwrap()` so a
            // stdin-not-a-TTY error does not panic the CLI and
            // leak the master password string on the unwind.
            let pw = match rpassword::prompt_password("Set master password: ") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read master password: {e}");
                    return;
                }
            };
            let confirm = match rpassword::prompt_password("Confirm master password: ") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read master password: {e}");
                    return;
                }
            };
            if pw != confirm {
                eprintln!("Passwords do not match.");
                return;
            }
            let root = bitnet_kdbx::Group {
                uuid: [0u8; 16],
                name: zeroize::Zeroizing::new("Root".to_string()),
                children: vec![],
                entries: vec![],
            };
            match bitnet_kdbx::save_vault(&path, &[root], pw.as_bytes()) {
                Ok(()) => println!("Vault created at {}", path),
                Err(e) => eprintln!("Failed to create vault: {}", e),
            }
        }
    }
}

/// Interactive REPL: keep a single SessionManager alive across commands so
/// the user unlocks once, then issues many `list` / `get` / `totp` calls
/// without re-entering the master password.
fn run_repl(manager: SessionManager, no_echo_flag: bool) {
    eprintln!("BitNet REPL. Type 'help' for commands, 'quit' to exit.");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut no_echo = no_echo_flag;
    loop {
        print!("bitnet> ");
        let _ = stdout.flush();
        let mut line = String::new();
        let n = match stdin.lock().read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let cmd = match parts.next() {
            Some(c) => c,
            None => continue,
        };
        let args: Vec<&str> = parts.collect();
        match cmd {
            "quit" | "exit" => break,
            "help" => print_repl_help(),
            "echo" => {
                no_echo = !no_echo;
                eprintln!("echo {}", if no_echo { "off" } else { "on" });
            }
            "unlock" => {
                if args.is_empty() {
                    eprintln!("usage: unlock <path>");
                    continue;
                }
                if !util::validate_vault_path(args[0]) {
                    eprintln!("Invalid vault path.");
                    continue;
                }
                // [BITNET-M5] CWE-755: avoid `unwrap()` so a
                // stdin-not-a-TTY error does not panic the REPL
                // and leak the master password string on the
                // unwind.
                let pw = match rpassword::prompt_password("Master password: ") {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Failed to read master password: {e}");
                        continue;
                    }
                };
                match manager.unlock(args[0], pw.as_bytes()) {
                    Ok(()) => eprintln!("Vault unlocked."),
                    Err(e) => eprintln!("Unlock failed: {}", e),
                }
            }
            "lock" => {
                manager.lock();
                eprintln!("Vault locked.");
            }
            "list" => match manager.list_entries() {
                Ok(entries) => {
                    for entry in entries {
                        let totp = if entry.has_totp { " [TOTP]" } else { "" };
                        println!(
                            "{} - {}{}",
                            hex_uuid(&entry.uuid),
                            entry.title.as_str(),
                            totp
                        );
                    }
                }
                Err(e) => {
                    log_error("list entries", &e);
                    eprintln!("Error: {}", e)
                }
            },
            "get" => {
                if args.is_empty() {
                    eprintln!("usage: get <uuid>");
                    continue;
                }
                let Some(uuid) = parse_hex_uuid(args[0]) else {
                    eprintln!("Invalid UUID format");
                    continue;
                };
                match manager.get_password(&uuid) {
                    Ok(password) => {
                        if !no_echo {
                            println!("{}", password.as_str());
                        }
                    }
                    Err(e) => {
                        log_error("list entries", &e);
                        eprintln!("Error: {}", e)
                    }
                }
            }
            "totp" => {
                if args.is_empty() {
                    eprintln!("usage: totp <uuid>");
                    continue;
                }
                let Some(uuid) = parse_hex_uuid(args[0]) else {
                    eprintln!("Invalid UUID format");
                    continue;
                };
                match manager.get_totp(&uuid) {
                    Ok(Some((code, remaining))) => {
                        if !no_echo {
                            println!("Code: {} (expires in {}s)", code, remaining);
                        }
                    }
                    Ok(None) => println!("No TOTP configured for this entry."),
                    Err(e) => {
                        log_error("list entries", &e);
                        eprintln!("Error: {}", e)
                    }
                }
            }
            "generate" => {
                let len = args
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(16);
                let flags = PasswordGeneratorFlags {
                    length: len,
                    include_uppercase: true,
                    include_lowercase: true,
                    include_digits: true,
                    include_symbols: true,
                    exclude_ambiguous: false,
                };
                let pwd = manager.generate_password(&flags);
                if !no_echo {
                    println!("{}", pwd);
                }
            }
            other => eprintln!("Unknown command: {} (type 'help')", other),
        }
    }
}

fn print_repl_help() {
    eprintln!(
        "Commands:\n  \
         unlock <path>  Unlock a vault\n  \
         lock           Lock the current session\n  \
         list           List all entries\n  \
         get <uuid>     Print password for an entry\n  \
         totp <uuid>    Print TOTP code for an entry\n  \
         generate [len] Generate a random password (default 16)\n  \
         echo           Toggle printing of secrets\n  \
         help           Show this help\n  \
         quit           Exit REPL"
    );
}

fn parse_hex_uuid(s: &str) -> Option<[u8; 16]> {
    util::uuid_from_hex(s)
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    util::hex_encode(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitnet_core::SessionManager;

    #[test]
    fn test_parse_hex_uuid_valid() {
        let uuid = parse_hex_uuid("550e8400e29b41d4a716446655440000").unwrap();
        assert_eq!(uuid.len(), 16);
        assert_eq!(hex_uuid(&uuid), "550e8400e29b41d4a716446655440000");
    }

    /// P1 #3 regression: a --password CLI flag must NOT be accepted.
    /// Passwords are sensitive and can leak via process listings / shell history
    /// if passed on the command line. Master passwords are read interactively
    /// from the TTY instead.
    #[test]
    fn test_no_password_cli_flag_rejected() {
        use clap::Parser;
        let args_ok: Vec<&str> = vec!["bitnet-cli", "list"];
        assert!(Cli::try_parse_from(args_ok).is_ok());
        let args_bad: Vec<&str> = vec!["bitnet-cli", "--password", "secret", "list"];
        let res = Cli::try_parse_from(args_bad);
        assert!(res.is_err(), "no --password flag should be accepted");
    }

    #[test]
    fn test_parse_hex_uuid_with_dashes() {
        let uuid = parse_hex_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(hex_uuid(&uuid), "550e8400e29b41d4a716446655440000");
    }

    #[test]
    fn test_parse_hex_uuid_invalid_length() {
        assert!(parse_hex_uuid("too-short").is_none());
        assert!(parse_hex_uuid(&"a".repeat(33)).is_none());
    }

    #[test]
    fn test_parse_hex_uuid_invalid_chars() {
        assert!(parse_hex_uuid("gggggggggggggggggggggggggggggggg").is_none());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(util::hex_encode(b"hello"), "68656c6c6f");
        assert_eq!(util::hex_encode(b""), "");
    }

    #[test]
    fn test_create_and_unlock_vault() {
        let path = "test_cli_vault.bitnet";
        let password = b"cli_test_password";

        let root = bitnet_kdbx::Group {
            uuid: [0u8; 16],
            name: zeroize::Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![bitnet_kdbx::Entry {
                uuid: [1u8; 16],
                title: zeroize::Zeroizing::new("TestEntry".to_string()),
                username: zeroize::Zeroizing::new("testuser".to_string()),
                password: zeroize::Zeroizing::new("testpass123".to_string()),
                url: zeroize::Zeroizing::new("https://example.com".to_string()),
                notes: zeroize::Zeroizing::new("".to_string()),
                totp_secret: Some(zeroize::Zeroizing::new("JBSWY3DPEHPK3PXP".to_string())),
                totp_digits: None,
                totp_period: None,
                created_at: 0,
                updated_at: 0,
                accessed_at: 0,
            }],
        };
        bitnet_kdbx::save_vault(path, &[root], password).unwrap();

        let manager = SessionManager::new();
        manager.unlock(path, password).unwrap();
        assert_eq!(manager.state(), bitnet_core::SessionState::Unlocked);

        let entries = manager.list_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title.as_str(), "TestEntry");
        assert_eq!(entries[0].username.as_str(), "testuser");
        assert!(entries[0].has_totp);

        let pwd = manager.get_password(&[1u8; 16]).unwrap();
        assert_eq!(pwd.as_str(), "testpass123");

        let totp = manager.get_totp(&[1u8; 16]).unwrap();
        assert!(totp.is_some());
        let (code, remaining) = totp.unwrap();
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30);

        manager.lock();
        assert_eq!(manager.state(), bitnet_core::SessionState::Locked);

        let data = std::fs::read(path).unwrap();
        let hash = bitnet_crypto::sha256(&data);
        let hex = util::hex_encode(&hash);
        assert_eq!(hex.len(), 64);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_password_generator_flags() {
        let flags = PasswordGeneratorFlags {
            length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: false,
            exclude_ambiguous: true,
        };
        let pwd = bitnet_crypto::generate_password(&flags);
        assert_eq!(pwd.len(), 20);
        assert!(!pwd
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
    }

    #[test]
    fn test_cli_info_fingerprint() {
        let path = "test_info.bitnet";
        let root = bitnet_kdbx::Group {
            uuid: [0u8; 16],
            name: zeroize::Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![],
        };
        bitnet_kdbx::save_vault(path, &[root], b"password").unwrap();
        let data = std::fs::read(path).unwrap();
        let hash = bitnet_crypto::sha256(&data);
        let hex = util::hex_encode(&hash);
        assert_eq!(hex.len(), 64);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_cli_create_command() {
        let path = "test_create_cmd.bitnet";
        let root = bitnet_kdbx::Group {
            uuid: [0u8; 16],
            name: zeroize::Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![bitnet_kdbx::Entry {
                uuid: [1u8; 16],
                title: zeroize::Zeroizing::new("Email".to_string()),
                username: zeroize::Zeroizing::new("user".to_string()),
                password: zeroize::Zeroizing::new("pass".to_string()),
                url: zeroize::Zeroizing::new("".to_string()),
                notes: zeroize::Zeroizing::new("".to_string()),
                totp_secret: None,
                totp_digits: None,
                totp_period: None,
                created_at: 0,
                updated_at: 0,
                accessed_at: 0,
            }],
        };
        bitnet_kdbx::save_vault(path, &[root], b"masterpass").unwrap();
        let loaded = bitnet_kdbx::load_vault(path, b"masterpass").unwrap();
        assert_eq!(loaded[0].entries.len(), 1);
        assert_eq!(loaded[0].entries[0].title.as_str(), "Email");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_totp_sha256_roundtrip() {
        use bitnet_totp::{generate_totp, verify_totp, TotpAlgorithm};
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let now = 59u64;
        let (code, _) = generate_totp(secret, now, TotpAlgorithm::Sha256).unwrap();
        assert_eq!(code.len(), 6);
        assert!(verify_totp(secret, now, &code, TotpAlgorithm::Sha256).unwrap());
    }

    #[test]
    fn test_validate_vault_path_cli() {
        assert!(util::validate_vault_path("C:\\Users\\user\\vault.bitnet"));
        assert!(!util::validate_vault_path(
            "C:\\Windows\\System32\\config\\SAM"
        ));
        assert!(!util::validate_vault_path("C:\\Users\\..\\vault.bitnet"));
        assert!(!util::validate_vault_path("C:\\Users\\vault.txt"));
    }
}
