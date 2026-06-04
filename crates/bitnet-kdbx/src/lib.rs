use bitnet_crypto::{decrypt, derive_key, encrypt, generate_salt, hmac_sha256};
use std::fs;
use std::io::{Read, Write};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"BITNET01";
const VERSION: u32 = 0x0001_0000;

/// Represents a group (folder) of password entries.
#[derive(Debug, Clone)]
pub struct Group {
    pub uuid: [u8; 16],
    pub name: Zeroizing<String>,
    pub children: Vec<Group>,
    pub entries: Vec<Entry>,
}

/// Represents a single password entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub uuid: [u8; 16],
    pub title: Zeroizing<String>,
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub url: Zeroizing<String>,
    pub notes: Zeroizing<String>,
    pub totp_secret: Option<Zeroizing<String>>,
    /// TOTP code length; None → RFC default of 6.
    pub totp_digits: Option<u32>,
    /// TOTP time step in seconds; None → RFC default of 30.
    pub totp_period: Option<u32>,
    /// Epoch seconds when the entry was first created. 0 if unknown.
    pub created_at: u64,
    /// Epoch seconds of the last mutation. 0 if unknown.
    pub updated_at: u64,
    /// Epoch seconds of the most recent read. 0 if unknown.
    pub accessed_at: u64,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            uuid: [0u8; 16],
            title: Zeroizing::new(String::new()),
            username: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            url: Zeroizing::new(String::new()),
            notes: Zeroizing::new(String::new()),
            totp_secret: None,
            totp_digits: None,
            totp_period: None,
            created_at: 0,
            updated_at: 0,
            accessed_at: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum KdbxError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Decryption failed: invalid password or corrupted file")]
    DecryptionFailed,
    #[error("Invalid file format")]
    InvalidFormat,
    #[error("HMAC verification failed")]
    HmacFailed,
}

/// Vault header.
#[derive(Debug)]
struct VaultHeader {
    magic: [u8; 8],
    version: u32,
    salt: [u8; 32],
    nonce: [u8; 12],
    argon2_time: u32,
    argon2_memory: u32,
    argon2_parallelism: u32,
}

const HEADER_SIZE: usize = 68;

impl VaultHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.argon2_time.to_be_bytes());
        buf.extend_from_slice(&self.argon2_memory.to_be_bytes());
        buf.extend_from_slice(&self.argon2_parallelism.to_be_bytes());
        assert_eq!(buf.len(), HEADER_SIZE);
        buf
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KdbxError> {
        if data.len() < HEADER_SIZE {
            return Err(KdbxError::InvalidFormat);
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);
        if magic.as_ref() != MAGIC {
            return Err(KdbxError::InvalidFormat);
        }
        let version = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        if version != VERSION {
            return Err(KdbxError::InvalidFormat);
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[12..44]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[44..56]);
        let argon2_time = u32::from_be_bytes([data[56], data[57], data[58], data[59]]);
        let argon2_memory = u32::from_be_bytes([data[60], data[61], data[62], data[63]]);
        let argon2_parallelism = u32::from_be_bytes([data[64], data[65], data[66], data[67]]);
        Ok(Self {
            magic,
            version,
            salt,
            nonce,
            argon2_time,
            argon2_memory,
            argon2_parallelism,
        })
    }
}

fn serialize_entries(entries: &[Group]) -> Vec<u8> {
    let mut buf = Vec::new();
    for group in entries {
        serialize_group(&mut buf, group);
    }
    buf
}

fn serialize_group(buf: &mut Vec<u8>, group: &Group) {
    buf.push(0x01);
    buf.extend_from_slice(&group.uuid);
    serialize_string(buf, &group.name);
    buf.extend_from_slice(&((group.children.len() as u32).to_be_bytes()));
    for child in &group.children {
        serialize_group(buf, child);
    }
    buf.extend_from_slice(&((group.entries.len() as u32).to_be_bytes()));
    for entry in &group.entries {
        buf.push(0x02);
        buf.extend_from_slice(&entry.uuid);
        serialize_string(buf, &entry.title);
        serialize_string(buf, &entry.username);
        serialize_string(buf, &entry.password);
        serialize_string(buf, &entry.url);
        serialize_string(buf, &entry.notes);
        let has_totp = entry.totp_secret.is_some() as u8;
        buf.push(has_totp);
        if let Some(ref secret) = entry.totp_secret {
            serialize_string(buf, secret);
            // 0xFF marks that extended TOTP params follow (digits/period).
            // Old format (no marker) is treated as RFC defaults (6/30).
            buf.push(0xFF);
            buf.extend_from_slice(&entry.totp_digits.unwrap_or(6).to_be_bytes());
            buf.extend_from_slice(&entry.totp_period.unwrap_or(30).to_be_bytes());
        }
        // 0xFE marks that timestamp fields follow (created/updated/accessed,
        // each u64 LE = 24 bytes total). Absent marker means timestamps are
        // unknown (0) — preserved for backward compatibility.
        buf.push(0xFE);
        buf.extend_from_slice(&entry.created_at.to_be_bytes());
        buf.extend_from_slice(&entry.updated_at.to_be_bytes());
        buf.extend_from_slice(&entry.accessed_at.to_be_bytes());
    }
}

fn serialize_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&((bytes.len() as u32).to_be_bytes()));
    buf.extend_from_slice(bytes);
}

const MAX_DESERIALIZE_DEPTH: usize = 256;
const MAX_TOTAL_GROUPS: usize = 50_000;
const MAX_TOTAL_ENTRIES: usize = 100_000;

fn deserialize_entries(data: &[u8]) -> Result<Vec<Group>, KdbxError> {
    let mut groups = Vec::new();
    let mut offset = 0usize;
    let mut total_groups = 0usize;
    let mut total_entries = 0usize;
    while offset < data.len() {
        if offset + 1 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let marker = data[offset];
        offset += 1;
        if marker != 0x01 {
            return Err(KdbxError::InvalidFormat);
        }
        let group = deserialize_group(data, &mut offset, 1, &mut total_groups, &mut total_entries)?;
        groups.push(group);
    }
    Ok(groups)
}

fn deserialize_group(
    data: &[u8],
    offset: &mut usize,
    depth: usize,
    total_groups: &mut usize,
    total_entries: &mut usize,
) -> Result<Group, KdbxError> {
    if depth > MAX_DESERIALIZE_DEPTH {
        return Err(KdbxError::InvalidFormat);
    }
    *total_groups = total_groups
        .checked_add(1)
        .ok_or(KdbxError::InvalidFormat)?;
    if *total_groups > MAX_TOTAL_GROUPS {
        return Err(KdbxError::InvalidFormat);
    }
    if *offset + 16 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[*offset..*offset + 16]);
    *offset += 16;

    let name = deserialize_string_zeroizing(data, offset)?;

    if *offset + 4 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let child_count = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]) as usize;
    *offset += 4;

    let mut children = Vec::new();
    for _ in 0..child_count {
        if *offset + 1 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let marker = data[*offset];
        *offset += 1;
        if marker != 0x01 {
            return Err(KdbxError::InvalidFormat);
        }
        children.push(deserialize_group(
            data,
            offset,
            depth + 1,
            total_groups,
            total_entries,
        )?);
    }

    if *offset + 4 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let entry_count = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]) as usize;
    *offset += 4;

    let mut entries = Vec::new();
    for _ in 0..entry_count {
        if *offset + 1 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let marker = data[*offset];
        *offset += 1;
        if marker != 0x02 {
            return Err(KdbxError::InvalidFormat);
        }

        if *offset + 16 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let mut entry_uuid = [0u8; 16];
        entry_uuid.copy_from_slice(&data[*offset..*offset + 16]);
        *offset += 16;

        let title = deserialize_string_zeroizing(data, offset)?;
        let username = deserialize_string_zeroizing(data, offset)?;
        let password = deserialize_string_zeroizing(data, offset)?;
        let url = deserialize_string_zeroizing(data, offset)?;
        let notes = deserialize_string_zeroizing(data, offset)?;

        *total_entries = total_entries
            .checked_add(1)
            .ok_or(KdbxError::InvalidFormat)?;
        if *total_entries > MAX_TOTAL_ENTRIES {
            return Err(KdbxError::InvalidFormat);
        }

        if *offset + 1 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let has_totp = data[*offset] != 0;
        *offset += 1;

        let totp_secret = if has_totp {
            Some(deserialize_string_zeroizing(data, offset)?)
        } else {
            None
        };

        // Optional extended TOTP parameters, introduced after the secret as:
        //   0xFF marker | digits (u32 BE) | period (u32 BE)
        // When the marker is absent (old format), fall back to RFC defaults.
        let mut totp_digits = None;
        let mut totp_period = None;
        if totp_secret.is_some() && *offset < data.len() && data[*offset] == 0xFF {
            *offset += 1;
            if *offset + 8 > data.len() {
                return Err(KdbxError::InvalidFormat);
            }
            let digits = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]);
            *offset += 4;
            let period = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]);
            *offset += 4;
            totp_digits = Some(digits);
            totp_period = Some(period);
        }

        // Optional timestamps block (introduced after TOTP, present on
        // every entry regardless of TOTP). Absent marker means the entry
        // was written by an old build and timestamps default to 0.
        let mut created_at: u64 = 0;
        let mut updated_at: u64 = 0;
        let mut accessed_at: u64 = 0;
        if *offset < data.len() && data[*offset] == 0xFE {
            *offset += 1;
            if *offset + 24 > data.len() {
                return Err(KdbxError::InvalidFormat);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[*offset..*offset + 8]);
            created_at = u64::from_be_bytes(b);
            *offset += 8;
            b.copy_from_slice(&data[*offset..*offset + 8]);
            updated_at = u64::from_be_bytes(b);
            *offset += 8;
            b.copy_from_slice(&data[*offset..*offset + 8]);
            accessed_at = u64::from_be_bytes(b);
            *offset += 8;
        }

        entries.push(Entry {
            uuid: entry_uuid,
            title,
            username,
            password,
            url,
            notes,
            totp_secret,
            totp_digits,
            totp_period,
            created_at,
            updated_at,
            accessed_at,
        });
    }

    Ok(Group {
        uuid,
        name,
        children,
        entries,
    })
}

fn deserialize_string_zeroizing(
    data: &[u8],
    offset: &mut usize,
) -> Result<Zeroizing<String>, KdbxError> {
    if *offset + 4 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let len = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]) as usize;
    *offset += 4;
    let end = offset.checked_add(len).ok_or(KdbxError::InvalidFormat)?;
    if end > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let s = String::from_utf8(data[*offset..end].to_vec()).map_err(|_| KdbxError::InvalidFormat)?;
    *offset = end;
    Ok(Zeroizing::new(s))
}

/// Save groups to an encrypted vault file.
pub fn save_vault(path: &str, groups: &[Group], master_password: &[u8]) -> Result<(), KdbxError> {
    use std::path::Path;

    // --- 1. Сгенерировать материалы ---
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&generate_salt(32));
    let key = derive_key(master_password, &salt);
    let plaintext = serialize_entries(groups);
    let (ciphertext, nonce) = encrypt(&plaintext, &key);

    let header = VaultHeader {
        magic: MAGIC.try_into().unwrap(),
        version: VERSION,
        salt,
        nonce,
        argon2_time: 3,
        argon2_memory: 64 * 1024,
        argon2_parallelism: 4,
    };
    let header_bytes = header.to_bytes();
    // P0 #1: domain-separated HMAC key (prevents cross-vault key reuse).
    let hmac_key = derive_key(
        master_password,
        &[b"bitnet-hmac-v1", salt.as_ref()].concat(),
    );
    let header_hmac = hmac_sha256(&*hmac_key, &header_bytes);

    // --- 2. Backup существующего файла (best-effort) ---
    let backup_path = format!("{}.bak", path);
    if Path::new(path).exists() {
        if let Ok(meta) = std::fs::metadata(&backup_path) {
            let mut perms = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(&backup_path, perms);
        }
        let _ = std::fs::copy(path, &backup_path);
    }

    // --- 3. Запись во временный файл ---
    let temp_path = format!("{}.tmp", path);
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(&header_bytes)?;
        file.write_all(&header_hmac)?;
        // P1 #23: explicit u64 for cross-platform compatibility.
        let len = ciphertext.len() as u64;
        file.write_all(&len.to_be_bytes())?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
    }

    // --- 4. Атомарный rename ---
    fs::rename(&temp_path, path)?;
    Ok(())
}

/// Load groups from an encrypted vault file.
pub fn load_vault(path: &str, master_password: &[u8]) -> Result<Vec<Group>, KdbxError> {
    let mut file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < HEADER_SIZE + 32 + 8 {
        return Err(KdbxError::InvalidFormat);
    }

    let header = VaultHeader::from_bytes(&data)?;
    let stored_hmac: [u8; 32] = data[HEADER_SIZE..HEADER_SIZE + 32].try_into().unwrap();
    // P0 #1: domain-separated HMAC key (must match save_vault).
    let hmac_key = derive_key(
        master_password,
        &[b"bitnet-hmac-v1", header.salt.as_ref()].concat(),
    );
    let computed_hmac = hmac_sha256(&*hmac_key, &data[..HEADER_SIZE]);

    if !bitnet_crypto::secure_compare(&stored_hmac, &computed_hmac) {
        return Err(KdbxError::HmacFailed);
    }

    let payload_len =
        u64::from_be_bytes(data[HEADER_SIZE + 32..HEADER_SIZE + 40].try_into().unwrap()) as usize;
    // P1 #23: sanity check on 32-bit systems where usize < u64::MAX.
    // Always true on 64-bit, so allow the absurd comparison.
    #[allow(clippy::absurd_extreme_comparisons)]
    {
        debug_assert!(payload_len <= usize::MAX);
    }
    const MAX_CIPHERTEXT_LENGTH: usize = 100 * 1024 * 1024;
    if payload_len > MAX_CIPHERTEXT_LENGTH {
        return Err(KdbxError::InvalidFormat);
    }
    if data.len() < HEADER_SIZE + 40 + payload_len {
        return Err(KdbxError::InvalidFormat);
    }
    let ciphertext = &data[HEADER_SIZE + 40..HEADER_SIZE + 40 + payload_len];

    let key = derive_key(master_password, &header.salt);
    let plaintext = decrypt(ciphertext, &key, &header.nonce).ok_or(KdbxError::DecryptionFailed)?;

    deserialize_entries(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let entry = Entry {
            uuid: [1u8; 16],
            title: Zeroizing::new("GitHub".to_string()),
            username: Zeroizing::new("alice".to_string()),
            password: Zeroizing::new("secret123".to_string()),
            url: Zeroizing::new("https://github.com".to_string()),
            notes: Zeroizing::new("".to_string()),
            totp_secret: Some(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
            ..Default::default()
        };
        let group = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![entry],
        };
        let path = "test_vault.bitnet";
        save_vault(path, &[group], b"master_password").unwrap();
        let loaded = load_vault(path, b"master_password").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].entries[0].title.as_str(), "GitHub");
        assert_eq!(loaded[0].entries[0].username.as_str(), "alice");
        assert_eq!(loaded[0].entries[0].password.as_str(), "secret123");
        fs::remove_file(path).unwrap();
    }

    /// P0 #1: domain-separated HMAC. Two vaults with the same password
    /// but different salts must have different HMAC keys. Swapping the
    /// header of vault A into vault B must fail HMAC verification.
    #[test]
    fn test_hmac_per_vault_isolation() {
        let pw = b"same_password";
        let g = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("R".into()),
            children: vec![],
            entries: vec![],
        };

        save_vault("a.bitnet", std::slice::from_ref(&g), pw).unwrap();
        save_vault("b.bitnet", std::slice::from_ref(&g), pw).unwrap();

        // Read a's header (68 bytes) and paste it into b → load must fail.
        let a = std::fs::read("a.bitnet").unwrap();
        let mut b = std::fs::read("b.bitnet").unwrap();
        let header_len = 68;
        b[..header_len].copy_from_slice(&a[..header_len]);
        std::fs::write("b.bitnet", &b).unwrap();

        let result = load_vault("b.bitnet", pw);
        assert!(matches!(result, Err(KdbxError::HmacFailed)));

        std::fs::remove_file("a.bitnet").ok();
        std::fs::remove_file("b.bitnet").ok();
    }

    /// P0 #2 + P2 #8: save_vault must create a .bak on overwrite and
    /// the .bak must contain the previous vault contents verbatim.
    #[test]
    fn test_save_creates_backup_on_overwrite() {
        let g = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("R".into()),
            children: vec![],
            entries: vec![],
        };
        save_vault("test_atomic.bitnet", std::slice::from_ref(&g), b"pw").unwrap();
        let original = std::fs::read("test_atomic.bitnet").unwrap();

        save_vault("test_atomic.bitnet", std::slice::from_ref(&g), b"pw").unwrap();

        assert!(std::path::Path::new("test_atomic.bitnet.bak").exists());
        let backup = std::fs::read("test_atomic.bitnet.bak").unwrap();
        assert_eq!(original, backup);

        std::fs::remove_file("test_atomic.bitnet").ok();
        std::fs::remove_file("test_atomic.bitnet.bak").ok();
    }

    /// P0 #2: large vault (50 entries) round-trips correctly after the
    /// atomic-write refactor.
    #[test]
    fn test_atomic_large_vault_roundtrip() {
        let mut entries = vec![];
        for i in 0..50u8 {
            entries.push(Entry {
                uuid: [i; 16],
                title: Zeroizing::new(format!("E{}", i)),
                ..Default::default()
            });
        }
        let g = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("R".into()),
            children: vec![],
            entries,
        };
        save_vault("test_crash.bitnet", &[g], b"pw").unwrap();
        let loaded = load_vault("test_crash.bitnet", b"pw").unwrap();
        assert_eq!(loaded[0].entries.len(), 50);
        std::fs::remove_file("test_crash.bitnet").ok();
        std::fs::remove_file("test_crash.bitnet.bak").ok();
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_multiple_entries() {
        let entries = vec![
            Entry {
                uuid: [1u8; 16],
                title: Zeroizing::new("GitHub".to_string()),
                username: Zeroizing::new("alice".to_string()),
                password: Zeroizing::new("pass1".to_string()),
                url: Zeroizing::new("https://github.com".to_string()),
                notes: Zeroizing::new("".to_string()),
                totp_secret: None,
                ..Default::default()
            },
            Entry {
                uuid: [2u8; 16],
                title: Zeroizing::new("Gmail".to_string()),
                username: Zeroizing::new("bob".to_string()),
                password: Zeroizing::new("pass2".to_string()),
                url: Zeroizing::new("https://gmail.com".to_string()),
                notes: Zeroizing::new("important".to_string()),
                totp_secret: Some(Zeroizing::new("SECRET123".into())),
                ..Default::default()
            },
        ];
        let group = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries,
        };
        let path = "test_multi.bitnet";
        save_vault(path, &[group], b"master").unwrap();
        let loaded = load_vault(path, b"master").unwrap();
        assert_eq!(loaded[0].entries.len(), 2);
        assert_eq!(loaded[0].entries[0].title.as_str(), "GitHub");
        assert_eq!(loaded[0].entries[1].title.as_str(), "Gmail");
        assert_eq!(loaded[0].entries[1].password.as_str(), "pass2");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_nested_groups() {
        let child = Group {
            uuid: [2u8; 16],
            name: Zeroizing::new("Work".to_string()),
            children: vec![],
            entries: vec![Entry {
                uuid: [3u8; 16],
                title: Zeroizing::new("Work VPN".to_string()),
                username: Zeroizing::new("employee".to_string()),
                password: Zeroizing::new("vpn123".to_string()),
                url: Zeroizing::new("".to_string()),
                notes: Zeroizing::new("".to_string()),
                totp_secret: None,
                ..Default::default()
            }],
        };
        let root = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![child],
            entries: vec![],
        };
        let path = "test_nested.bitnet";
        save_vault(path, &[root], b"master").unwrap();
        let loaded = load_vault(path, b"master").unwrap();
        assert_eq!(loaded[0].children.len(), 1);
        assert_eq!(loaded[0].children[0].name.as_str(), "Work");
        assert_eq!(loaded[0].children[0].entries[0].title.as_str(), "Work VPN");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_wrong_password_fails() {
        let entry = Entry {
            uuid: [1u8; 16],
            title: Zeroizing::new("Test".to_string()),
            username: Zeroizing::new("u".to_string()),
            password: Zeroizing::new("p".to_string()),
            url: Zeroizing::new("".to_string()),
            notes: Zeroizing::new("".to_string()),
            totp_secret: None,
            ..Default::default()
        };
        let group = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![entry],
        };
        let path = "test_wrong.bitnet";
        save_vault(path, &[group], b"correct").unwrap();
        let result = load_vault(path, b"wrong");
        assert!(matches!(result, Err(KdbxError::HmacFailed)));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_tampered_file_fails() {
        let entry = Entry {
            uuid: [1u8; 16],
            title: Zeroizing::new("Test".to_string()),
            username: Zeroizing::new("u".to_string()),
            password: Zeroizing::new("p".to_string()),
            url: Zeroizing::new("".to_string()),
            notes: Zeroizing::new("".to_string()),
            totp_secret: None,
            ..Default::default()
        };
        let group = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![entry],
        };
        let path = "test_tamper.bitnet";
        save_vault(path, &[group], b"master").unwrap();

        let mut data = std::fs::read(path).unwrap();
        if data.len() > 100 {
            data[80] ^= 0xFF;
        }
        std::fs::write(path, &data).unwrap();

        let result = load_vault(path, b"master");
        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_malformed_vault_bounds_check() {
        // Empty plaintext after decryption would result in empty data passed to deserialize_entries
        let result = deserialize_entries(b"");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);

        // Truncated group marker only
        let result = deserialize_entries(b"\x01");
        assert!(matches!(result, Err(KdbxError::InvalidFormat)));

        // Truncated after marker (not enough bytes for UUID)
        let result = deserialize_entries(
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        assert!(matches!(result, Err(KdbxError::InvalidFormat)));

        // Valid header + marker + UUID + partial name length
        let mut buf = vec![0x01u8];
        buf.extend_from_slice(&[0u8; 16]); // uuid
                                           // name length = 4, but no name bytes follow
        buf.extend_from_slice(&[0u8, 0u8, 0u8, 4u8]);
        let result = deserialize_entries(&buf);
        assert!(matches!(result, Err(KdbxError::InvalidFormat)));
    }

    #[test]
    fn test_deserialize_depth_exceeded() {
        // Build a chain of 257 nested groups (depth 1..257).
        // deserialize_group rejects depth > 256.
        let mut group = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("leaf".to_string()),
            children: vec![],
            entries: vec![],
        };
        for _ in 0..256 {
            group = Group {
                uuid: [0u8; 16],
                name: Zeroizing::new("inner".to_string()),
                children: vec![group],
                entries: vec![],
            };
        }
        let path = "test_depth.bitnet";
        save_vault(path, &[group], b"master").unwrap();
        let result = load_vault(path, b"master");
        assert!(
            matches!(result, Err(KdbxError::InvalidFormat)),
            "expected InvalidFormat for excessive nesting depth, got {:?}",
            result
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_deserialize_total_groups_exceeded() {
        // Create 50_001 top-level groups to exceed MAX_TOTAL_GROUPS (50_000).
        let mut groups = Vec::with_capacity(50_001);
        for _ in 0..50_001 {
            groups.push(Group {
                uuid: [0u8; 16],
                name: Zeroizing::new("g".to_string()),
                children: vec![],
                entries: vec![],
            });
        }
        let path = "test_total_groups.bitnet";
        save_vault(path, &groups, b"master").unwrap();
        let result = load_vault(path, b"master");
        assert!(
            matches!(result, Err(KdbxError::InvalidFormat)),
            "expected InvalidFormat for excessive total groups, got {:?}",
            result
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_ciphertext_too_large_rejected() {
        let header = VaultHeader {
            magic: *b"BITNET01",
            version: VERSION,
            salt: [0u8; 32],
            nonce: [0u8; 12],
            argon2_time: 3,
            argon2_memory: 64 * 1024,
            argon2_parallelism: 4,
        };
        let header_bytes = header.to_bytes();
        // P0 #1: HMAC key now uses domain separation.
        let hmac_key = derive_key(
            b"master_password",
            &[b"bitnet-hmac-v1", [0u8; 32].as_ref()].concat(),
        );
        let header_hmac = hmac_sha256(&*hmac_key, &header_bytes);

        let mut file = fs::File::create("test_payload_len.bitnet").unwrap();
        file.write_all(&header_bytes).unwrap();
        file.write_all(&header_hmac).unwrap();
        file.write_all(&u64::MAX.to_be_bytes()).unwrap();
        drop(file);

        let result = load_vault("test_payload_len.bitnet", b"master_password");
        assert!(
            matches!(result, Err(KdbxError::InvalidFormat)),
            "expected InvalidFormat for oversized payload_len, got {:?}",
            result
        );
        fs::remove_file("test_payload_len.bitnet").unwrap();
    }

    #[test]
    fn test_future_version_rejected() {
        let group = Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![],
        };
        let path = "test_future_ver.bitnet";
        save_vault(path, &[group], b"master").unwrap();

        let mut data = fs::read(path).unwrap();
        // Version field is bytes 8..12 in the header
        data[8..12].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        fs::write(path, &data).unwrap();

        let result = load_vault(path, b"master");
        assert!(
            matches!(result, Err(KdbxError::InvalidFormat)),
            "expected InvalidFormat for future version, got {:?}",
            result
        );
        fs::remove_file(path).unwrap();
    }
}
include!("../fuzz/fuzz_deserialize.rs");
