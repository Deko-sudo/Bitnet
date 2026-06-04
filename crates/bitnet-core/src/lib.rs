use bitnet_crypto::sha256;
use bitnet_kdbx::{load_vault, save_vault, Entry, Group, KdbxError};
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

pub mod locked;
pub mod session_token;
pub mod util;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Session locked")]
    SessionLocked,
    #[error("Entry not found")]
    EntryNotFound,
    #[error("Group not found")]
    GroupNotFound,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("KDBX error: {0}")]
    Kdbx(#[from] KdbxError),
    #[error("TOTP error: {0}")]
    Totp(#[from] bitnet_totp::TotpError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Locked,
    Unlocked,
}

/// Represents an active session with decrypted vault data.
pub struct Session {
    vault_path: Zeroizing<String>,
    groups: Vec<Group>,
    last_activity: Instant,
    auto_lock_duration: Duration,
}

impl Session {
    pub fn fingerprint(&self) -> String {
        let hash = sha256(self.vault_path.as_bytes());
        hex::encode(&hash[..8])
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > self.auto_lock_duration
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn find_entry(&self, uuid: &[u8; 16]) -> Option<&Entry> {
        Self::find_entry_in_groups(&self.groups, uuid)
    }

    pub fn find_entry_mut(&mut self, uuid: &[u8; 16]) -> Option<&mut Entry> {
        Self::find_entry_mut_in_groups(&mut self.groups, uuid)
    }

    pub fn find_group_mut(&mut self, uuid: &[u8; 16]) -> Option<&mut Group> {
        Self::find_group_mut_in_groups(&mut self.groups, uuid)
    }

    fn find_entry_in_groups<'a>(groups: &'a [Group], uuid: &[u8; 16]) -> Option<&'a Entry> {
        for group in groups {
            for entry in &group.entries {
                if &entry.uuid == uuid {
                    return Some(entry);
                }
            }
            if let Some(found) = Self::find_entry_in_groups(&group.children, uuid) {
                return Some(found);
            }
        }
        None
    }

    fn find_entry_mut_in_groups<'a>(
        groups: &'a mut [Group],
        uuid: &[u8; 16],
    ) -> Option<&'a mut Entry> {
        for group in groups {
            for entry in &mut group.entries {
                if &entry.uuid == uuid {
                    return Some(entry);
                }
            }
            if let Some(found) = Self::find_entry_mut_in_groups(&mut group.children, uuid) {
                return Some(found);
            }
        }
        None
    }

    fn find_group_mut_in_groups<'a>(
        groups: &'a mut [Group],
        uuid: &[u8; 16],
    ) -> Option<&'a mut Group> {
        for group in groups {
            if &group.uuid == uuid {
                return Some(group);
            }
            if let Some(found) = Self::find_group_mut_in_groups(&mut group.children, uuid) {
                return Some(found);
            }
        }
        None
    }
}

/// Centralized session manager implementing Zero Trust.
pub struct SessionManager {
    state: Mutex<Option<Session>>,
    default_auto_lock: Duration,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
            default_auto_lock: Duration::from_secs(300), // 5 minutes
        }
    }

    #[cfg(test)]
    pub fn with_auto_lock(duration: Duration) -> Self {
        Self {
            state: Mutex::new(None),
            default_auto_lock: duration,
        }
    }

    pub fn state(&self) -> SessionState {
        let guard = self.state.lock();
        match &*guard {
            Some(session) if !session.is_expired() => SessionState::Unlocked,
            _ => SessionState::Locked,
        }
    }

    pub fn create_vault(&self, vault_path: &str, master_password: &[u8]) -> Result<(), CoreError> {
        let root = Group {
            uuid: new_uuid(),
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![],
        };
        save_vault(vault_path, &[root], master_password)?;
        self.unlock(vault_path, master_password)
    }

    pub fn unlock(&self, vault_path: &str, master_password: &[u8]) -> Result<(), CoreError> {
        let groups = load_vault(vault_path, master_password)?;
        let mut state = self.state.lock();
        *state = Some(Session {
            vault_path: Zeroizing::new(vault_path.to_string()),
            groups,
            last_activity: Instant::now(),
            auto_lock_duration: self.default_auto_lock,
        });
        Ok(())
    }

    pub fn lock(&self) {
        let mut state = self.state.lock();
        *state = None;
    }

    pub fn ensure_unlocked(&self) -> Result<(), CoreError> {
        let guard = self.state.lock();
        match &*guard {
            Some(session) if !session.is_expired() => Ok(()),
            _ => Err(CoreError::SessionLocked),
        }
    }

    pub fn touch(&self) {
        let mut state = self.state.lock();
        if let Some(ref mut session) = *state {
            session.touch();
        }
    }

    pub fn get_password(&self, uuid: &[u8; 16]) -> Result<Zeroizing<String>, CoreError> {
        self.ensure_unlocked()?;
        let guard = self.state.lock();
        let session = guard.as_ref().ok_or(CoreError::SessionLocked)?;
        let entry = session.find_entry(uuid).ok_or(CoreError::EntryNotFound)?;
        Ok(entry.password.clone())
    }

    pub fn get_entry_details(
        &self,
        uuid: &[u8; 16],
    ) -> Result<(Zeroizing<String>, String), CoreError> {
        self.ensure_unlocked()?;
        let guard = self.state.lock();
        let session = guard.as_ref().ok_or(CoreError::SessionLocked)?;
        let entry = session.find_entry(uuid).ok_or(CoreError::EntryNotFound)?;
        Ok((entry.password.clone(), entry.username.to_string()))
    }

    pub fn get_totp(&self, uuid: &[u8; 16]) -> Result<Option<(String, u8)>, CoreError> {
        self.ensure_unlocked()?;
        let guard = self.state.lock();
        let session = guard.as_ref().ok_or(CoreError::SessionLocked)?;
        let entry = session.find_entry(uuid).ok_or(CoreError::EntryNotFound)?;
        if let Some(ref secret) = entry.totp_secret {
            let digits = entry.totp_digits.unwrap_or(6);
            let period = u64::from(entry.totp_period.unwrap_or(30));
            let (code, remaining) = bitnet_totp::generate_totp_with_params(
                secret,
                current_timestamp(),
                bitnet_totp::TotpAlgorithm::Sha1,
                digits,
                period,
            )?;
            Ok(Some((code, remaining)))
        } else {
            Ok(None)
        }
    }

    pub fn generate_password(&self, flags: &bitnet_crypto::PasswordGeneratorFlags) -> String {
        bitnet_crypto::generate_password(flags)
    }

    pub fn list_entries(&self) -> Result<Vec<EntrySummary>, CoreError> {
        self.ensure_unlocked()?;
        let guard = self.state.lock();
        let session = guard.as_ref().ok_or(CoreError::SessionLocked)?;
        let mut summaries = Vec::new();
        Self::collect_entries(&session.groups, &mut summaries);
        Ok(summaries)
    }

    fn collect_entries(groups: &[Group], out: &mut Vec<EntrySummary>) {
        for group in groups {
            for entry in &group.entries {
                out.push(EntrySummary {
                    uuid: entry.uuid,
                    title: entry.title.clone(),
                    username: entry.username.clone(),
                    url: entry.url.clone(),
                    has_totp: entry.totp_secret.is_some(),
                });
            }
            Self::collect_entries(&group.children, out);
        }
    }

    pub fn add_entry(&self, group_uuid: &[u8; 16], entry: Entry) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let mut state = self.state.lock();
        let session = state.as_mut().ok_or(CoreError::SessionLocked)?;
        if let Some(group) = session.find_group_mut(group_uuid) {
            group.entries.push(entry);
        } else {
            // Fallback: use first root group if uuid is all-zero or not found
            if let Some(first_group) = session.groups.first_mut() {
                first_group.entries.push(entry);
            } else {
                return Err(CoreError::GroupNotFound);
            }
        }
        session.touch();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_entry(
        &self,
        uuid: &[u8; 16],
        title: Option<String>,
        username: Option<String>,
        password: Option<Zeroizing<String>>,
        url: Option<String>,
        notes: Option<String>,
        totp_secret: Option<Option<Zeroizing<String>>>,
    ) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let mut state = self.state.lock();
        let session = state.as_mut().ok_or(CoreError::SessionLocked)?;
        let entry = session
            .find_entry_mut(uuid)
            .ok_or(CoreError::EntryNotFound)?;
        if let Some(t) = title {
            entry.title = Zeroizing::new(t);
        }
        if let Some(u) = username {
            entry.username = Zeroizing::new(u);
        }
        if let Some(p) = password {
            entry.password = p;
        }
        if let Some(u) = url {
            entry.url = Zeroizing::new(u);
        }
        if let Some(n) = notes {
            entry.notes = Zeroizing::new(n);
        }
        if let Some(t) = totp_secret {
            entry.totp_secret = t;
        }
        session.touch();
        Ok(())
    }

    pub fn delete_entry(&self, uuid: &[u8; 16]) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let mut state = self.state.lock();
        let session = state.as_mut().ok_or(CoreError::SessionLocked)?;
        let removed = Self::delete_entry_in_groups(&mut session.groups, uuid)?;
        if !removed {
            return Err(CoreError::EntryNotFound);
        }
        session.touch();
        Ok(())
    }

    fn delete_entry_in_groups(groups: &mut [Group], uuid: &[u8; 16]) -> Result<bool, CoreError> {
        for group in groups {
            if let Some(pos) = group.entries.iter().position(|e| &e.uuid == uuid) {
                group.entries.remove(pos);
                return Ok(true);
            }
            if Self::delete_entry_in_groups(&mut group.children, uuid)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn create_group(
        &self,
        parent_uuid: Option<&[u8; 16]>,
        name: &str,
    ) -> Result<[u8; 16], CoreError> {
        self.ensure_unlocked()?;
        let mut state = self.state.lock();
        let session = state.as_mut().ok_or(CoreError::SessionLocked)?;
        let uuid = new_uuid();
        let group = Group {
            uuid,
            name: Zeroizing::new(name.to_string()),
            children: vec![],
            entries: vec![],
        };
        if let Some(parent) = parent_uuid {
            let parent_group = session
                .find_group_mut(parent)
                .ok_or(CoreError::GroupNotFound)?;
            parent_group.children.push(group);
        } else {
            session.groups.push(group);
        }
        session.touch();
        Ok(uuid)
    }

    pub fn save(&self, vault_path: &str, master_password: &[u8]) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let guard = self.state.lock();
        let session = guard.as_ref().ok_or(CoreError::SessionLocked)?;
        save_vault(vault_path, &session.groups, master_password)?;
        Ok(())
    }

    /// Меняет мастер-пароль разблокированного vault'а.
    /// Требует активной unlocked-сессии и валидного `old_password` для проверки.
    pub fn change_master_password(
        &self,
        vault_path: &str,
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        // Verify old password by attempting to load the on-disk vault.
        // If the file was swapped, load_vault returns Err(KdbxError) and we
        // surface it as InvalidPassword to the caller.
        let _ = bitnet_kdbx::load_vault(vault_path, old_password)
            .map_err(|_| CoreError::InvalidPassword)?;
        // Re-encrypt the in-memory groups with the new password.
        self.save(vault_path, new_password)?;
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EntrySummary {
    #[serde(serialize_with = "serialize_uuid_hex")]
    pub uuid: [u8; 16],
    pub title: Zeroizing<String>,
    pub username: Zeroizing<String>,
    pub url: Zeroizing<String>,
    pub has_totp: bool,
}

fn serialize_uuid_hex<S: serde::Serializer>(
    uuid: &[u8; 16],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&util::hex_encode(uuid))
}

fn new_uuid() -> [u8; 16] {
    let uuid = uuid::Uuid::new_v4();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(uuid.as_bytes());
    bytes
}

fn current_timestamp() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lock_unlock() {
        let manager = SessionManager::new();
        assert_eq!(manager.state(), SessionState::Locked);
    }

    #[test]
    fn test_crud_operations() {
        let manager = SessionManager::new();
        let path = "test_crud.bitnet";
        manager.create_vault(path, b"master").unwrap();
        assert_eq!(manager.state(), SessionState::Unlocked);

        // Create group
        // Root group access not directly exposed via list_entries; fallback in add_entry handles it.
        // Actually, we need to access groups. Let's use save and reload to verify.

        // Add entry
        let entry = Entry {
            uuid: new_uuid(),
            title: Zeroizing::new("GitHub".to_string()),
            username: Zeroizing::new("alice".to_string()),
            password: Zeroizing::new("secret123".to_string()),
            url: Zeroizing::new("https://github.com".to_string()),
            notes: Zeroizing::new("".to_string()),
            totp_secret: None,
            totp_digits: None,
            totp_period: None,
            created_at: 0,
            updated_at: 0,
            accessed_at: 0,
        };
        // We need root uuid. Use first group from loaded vault.
        {
            let state = manager.state.lock();
            let session = state.as_ref().unwrap();
            let root_uuid = session.groups[0].uuid;
            drop(state);
            manager.add_entry(&root_uuid, entry.clone()).unwrap();
        }

        // Update entry
        manager
            .update_entry(
                &entry.uuid,
                Some("GitHub Updated".into()),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Verify update
        {
            let state = manager.state.lock();
            let session = state.as_ref().unwrap();
            let found = session.find_entry(&entry.uuid).unwrap();
            assert_eq!(found.title.as_str(), "GitHub Updated");
        }

        // Delete entry
        manager.delete_entry(&entry.uuid).unwrap();
        {
            let state = manager.state.lock();
            let session = state.as_ref().unwrap();
            assert!(session.find_entry(&entry.uuid).is_none());
        }

        // Save and reload
        manager.save(path, b"master").unwrap();
        manager.lock();
        manager.unlock(path, b"master").unwrap();
        {
            let state = manager.state.lock();
            let session = state.as_ref().unwrap();
            assert!(session.find_entry(&entry.uuid).is_none());
        }

        std::fs::remove_file(path).unwrap();
    }

    /// P1 #7: TOTP digits/period on the entry must be honoured by get_totp.
    /// An 8-digit TOTP secret must produce an 8-character code, not the
    /// default 6 digits.
    #[test]
    fn test_totp_8_digits_propagates_from_entry() {
        let manager = SessionManager::new();
        let path = "test_totp8.bitnet";
        manager.create_vault(path, b"master").unwrap();
        let entry_uuid = [42u8; 16];
        {
            let mut state = manager.state.lock();
            let session = state.as_mut().unwrap();
            let entry = Entry {
                uuid: entry_uuid,
                title: Zeroizing::new("8-digit".into()),
                username: Zeroizing::new("u".into()),
                password: Zeroizing::new("p".into()),
                url: Zeroizing::new("".into()),
                notes: Zeroizing::new("".into()),
                totp_secret: Some(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
                totp_digits: Some(8),
                totp_period: Some(30),
                created_at: 0,
                updated_at: 0,
                accessed_at: 0,
            };
            session.groups[0].entries.push(entry);
        }
        let result = manager.get_totp(&entry_uuid).unwrap().unwrap();
        assert_eq!(result.0.len(), 8, "8-digit TOTP should produce 8 chars");
        std::fs::remove_file(path).ok();
    }

    /// P1 #6: EntrySummary serialises uuid as a hex string so the C#
    /// WinUI frontend can match it against the JSON "uuid" field.
    #[test]
    fn test_entry_summary_uuid_is_hex_string() {
        let s = EntrySummary {
            uuid: [
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ],
            title: Zeroizing::new("GitHub".into()),
            username: Zeroizing::new("u".into()),
            url: Zeroizing::new("".into()),
            has_totp: false,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains(r#""uuid":"550e8400e29b41d4a716446655440000""#),
            "uuid must be hex string, got: {}",
            json
        );
    }
}

#[cfg(test)]
mod auto_lock_tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_auto_lock() {
        let manager = SessionManager::with_auto_lock(Duration::from_millis(100));
        let path = "test_autolock.bitnet";
        let root = bitnet_kdbx::Group {
            uuid: [0u8; 16],
            name: Zeroizing::new("Root".to_string()),
            children: vec![],
            entries: vec![],
        };
        bitnet_kdbx::save_vault(path, &[root], b"password").unwrap();
        manager.unlock(path, b"password").unwrap();
        assert_eq!(manager.state(), SessionState::Unlocked);
        thread::sleep(Duration::from_millis(200));
        assert_eq!(manager.state(), SessionState::Locked);
        std::fs::remove_file(path).unwrap();
    }
}
