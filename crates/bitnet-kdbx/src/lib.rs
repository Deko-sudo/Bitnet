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
    pub name: String,
    pub children: Vec<Group>,
    pub entries: Vec<Entry>,
}

/// Represents a single password entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub uuid: [u8; 16],
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    pub totp_secret: Option<Zeroizing<String>>,
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
        }
    }
}

fn serialize_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&((bytes.len() as u32).to_be_bytes()));
    buf.extend_from_slice(bytes);
}

fn deserialize_entries(data: &[u8]) -> Result<Vec<Group>, KdbxError> {
    let mut groups = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if offset + 1 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let marker = data[offset];
        offset += 1;
        if marker != 0x01 {
            return Err(KdbxError::InvalidFormat);
        }
        let group = deserialize_group(data, &mut offset)?;
        groups.push(group);
    }
    Ok(groups)
}

fn deserialize_group(data: &[u8], offset: &mut usize) -> Result<Group, KdbxError> {
    if *offset + 16 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[*offset..*offset + 16]);
    *offset += 16;

    let name = deserialize_string(data, offset)?;

    if *offset + 4 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let child_count = u32::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
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
        children.push(deserialize_group(data, offset)?);
    }

    if *offset + 4 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let entry_count = u32::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
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

        let title = deserialize_string(data, offset)?;
        let username = deserialize_string(data, offset)?;
        let password = Zeroizing::new(deserialize_string(data, offset)?);
        let url = deserialize_string(data, offset)?;
        let notes = deserialize_string(data, offset)?;

        if *offset + 1 > data.len() {
            return Err(KdbxError::InvalidFormat);
        }
        let has_totp = data[*offset] != 0;
        *offset += 1;

        let totp_secret = if has_totp {
            Some(Zeroizing::new(deserialize_string(data, offset)?))
        } else {
            None
        };

        entries.push(Entry {
            uuid: entry_uuid,
            title,
            username,
            password,
            url,
            notes,
            totp_secret,
        });
    }

    Ok(Group {
        uuid,
        name,
        children,
        entries,
    })
}

fn deserialize_string(data: &[u8], offset: &mut usize) -> Result<String, KdbxError> {
    if *offset + 4 > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let len = u32::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
    ]) as usize;
    *offset += 4;
    if *offset + len > data.len() {
        return Err(KdbxError::InvalidFormat);
    }
    let s = String::from_utf8(data[*offset..*offset + len].to_vec())
        .map_err(|_| KdbxError::InvalidFormat)?;
    *offset += len;
    Ok(s)
}

/// Save groups to an encrypted vault file.
pub fn save_vault(path: &str, groups: &[Group], master_password: &[u8]) -> Result<(), KdbxError> {
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
    let hmac_key = derive_key(master_password, &[0x01; 32]);
    let header_hmac = hmac_sha256(&*hmac_key, &header_bytes);

    let mut file = fs::File::create(path)?;
    file.write_all(&header_bytes)?;
    file.write_all(&header_hmac)?;
    file.write_all(&ciphertext.len().to_be_bytes())?;
    file.write_all(&ciphertext)?;
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
    let hmac_key = derive_key(master_password, &[0x01; 32]);
    let computed_hmac = hmac_sha256(&*hmac_key, &data[..HEADER_SIZE]);

    if !bitnet_crypto::secure_compare(&stored_hmac, &computed_hmac) {
        return Err(KdbxError::HmacFailed);
    }

    let payload_len = u64::from_be_bytes(data[HEADER_SIZE + 32..HEADER_SIZE + 40].try_into().unwrap()) as usize;
    if data.len() < HEADER_SIZE + 40 + payload_len {
        return Err(KdbxError::InvalidFormat);
    }
    let ciphertext = &data[HEADER_SIZE + 40..HEADER_SIZE + 40 + payload_len];

    let key = derive_key(master_password, &header.salt);
    let plaintext = decrypt(ciphertext, &key, &header.nonce)
        .ok_or(KdbxError::DecryptionFailed)?;

    deserialize_entries(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let entry = Entry {
            uuid: [1u8; 16],
            title: "GitHub".into(),
            username: "alice".into(),
            password: Zeroizing::new("secret123".into()),
            url: "https://github.com".into(),
            notes: "".into(),
            totp_secret: Some(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        };
        let group = Group {
            uuid: [0u8; 16],
            name: "Root".into(),
            children: vec![],
            entries: vec![entry],
        };
        let path = "test_vault.bitnet";
        save_vault(path, &[group], b"master_password").unwrap();
        let loaded = load_vault(path, b"master_password").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].entries[0].title, "GitHub");
        assert_eq!(loaded[0].entries[0].username, "alice");
        assert_eq!(loaded[0].entries[0].password.as_str(), "secret123");
        fs::remove_file(path).unwrap();
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
                title: "GitHub".into(),
                username: "alice".into(),
                password: Zeroizing::new("pass1".into()),
                url: "https://github.com".into(),
                notes: "".into(),
                totp_secret: None,
            },
            Entry {
                uuid: [2u8; 16],
                title: "Gmail".into(),
                username: "bob".into(),
                password: Zeroizing::new("pass2".into()),
                url: "https://gmail.com".into(),
                notes: "important".into(),
                totp_secret: Some(Zeroizing::new("SECRET123".into())),
            },
        ];
        let group = Group {
            uuid: [0u8; 16],
            name: "Root".into(),
            children: vec![],
            entries,
        };
        let path = "test_multi.bitnet";
        save_vault(path, &[group], b"master").unwrap();
        let loaded = load_vault(path, b"master").unwrap();
        assert_eq!(loaded[0].entries.len(), 2);
        assert_eq!(loaded[0].entries[0].title, "GitHub");
        assert_eq!(loaded[0].entries[1].title, "Gmail");
        assert_eq!(loaded[0].entries[1].password.as_str(), "pass2");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_nested_groups() {
        let child = Group {
            uuid: [2u8; 16],
            name: "Work".into(),
            children: vec![],
            entries: vec![Entry {
                uuid: [3u8; 16],
                title: "Work VPN".into(),
                username: "employee".into(),
                password: Zeroizing::new("vpn123".into()),
                url: "".into(),
                notes: "".into(),
                totp_secret: None,
            }],
        };
        let root = Group {
            uuid: [0u8; 16],
            name: "Root".into(),
            children: vec![child],
            entries: vec![],
        };
        let path = "test_nested.bitnet";
        save_vault(path, &[root], b"master").unwrap();
        let loaded = load_vault(path, b"master").unwrap();
        assert_eq!(loaded[0].children.len(), 1);
        assert_eq!(loaded[0].children[0].name, "Work");
        assert_eq!(loaded[0].children[0].entries[0].title, "Work VPN");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_wrong_password_fails() {
        let entry = Entry {
            uuid: [1u8; 16],
            title: "Test".into(),
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            url: "".into(),
            notes: "".into(),
            totp_secret: None,
        };
        let group = Group {
            uuid: [0u8; 16],
            name: "Root".into(),
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
            title: "Test".into(),
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            url: "".into(),
            notes: "".into(),
            totp_secret: None,
        };
        let group = Group {
            uuid: [0u8; 16],
            name: "Root".into(),
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
        let result = deserialize_entries(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(matches!(result, Err(KdbxError::InvalidFormat)));

        // Valid header + marker + UUID + partial name length
        let mut buf = vec![0x01u8];
        buf.extend_from_slice(&[0u8; 16]); // uuid
        // name length = 4, but no name bytes follow
        buf.extend_from_slice(&[0u8, 0u8, 0u8, 4u8]);
        let result = deserialize_entries(&buf);
        assert!(matches!(result, Err(KdbxError::InvalidFormat)));
    }
}
include!("../fuzz/fuzz_deserialize.rs");
