use bitnet_crypto::sha256;
use bitnet_kdbx::{Entry, Group, KdbxError, load_vault, save_vault};
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;


#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Session locked")]
    SessionLocked,
    #[error("Entry not found")]
    EntryNotFound,
    #[error("Group not found")]
    GroupNotFound,
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

    fn find_entry_mut_in_groups<'a>(groups: &'a mut [Group], uuid: &[u8; 16]) -> Option<&'a mut Entry> {
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

    fn find_group_mut_in_groups<'a>(groups: &'a mut [Group], uuid: &[u8; 16]) -> Option<&'a mut Group> {
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

    pub fn get_entry_details(&self, uuid: &[u8; 16]) -> Result<(Zeroizing<String>, String), CoreError> {
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
            let (code, remaining) = bitnet_totp::generate_totp(secret, current_timestamp(), bitnet_totp::TotpAlgorithm::Sha1)?;
            Ok(Some((code, remaining)))
        } else {
            Ok(None)
        }
    }

    pub fn generate_password(
        &self,
        flags: &bitnet_crypto::PasswordGeneratorFlags,
    ) -> Result<String, CoreError> {
        self.ensure_unlocked()?;
        Ok(bitnet_crypto::generate_password(flags))
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
    pub fn update_entry(&self, uuid: &[u8; 16], title: Option<String>, username: Option<String>, password: Option<Zeroizing<String>>, url: Option<String>, notes: Option<String>, totp_secret: Option<Option<Zeroizing<String>>>) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let mut state = self.state.lock();
        let session = state.as_mut().ok_or(CoreError::SessionLocked)?;
        let entry = session.find_entry_mut(uuid).ok_or(CoreError::EntryNotFound)?;
        if let Some(t) = title { entry.title = Zeroizing::new(t); }
        if let Some(u) = username { entry.username = Zeroizing::new(u); }
        if let Some(p) = password { entry.password = p; }
        if let Some(u) = url { entry.url = Zeroizing::new(u); }
        if let Some(n) = notes { entry.notes = Zeroizing::new(n); }
        if let Some(t) = totp_secret { entry.totp_secret = t; }
        session.touch();
        Ok(())
    }

    pub fn delete_entry(&self, uuid: &[u8; 16]) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let mut state = self.state.lock();
        let session = state.as_mut().ok_or(CoreError::SessionLocked)?;
        Self::delete_entry_in_groups(&mut session.groups, uuid)?;
        session.touch();
        Ok(())
    }

    fn delete_entry_in_groups(groups: &mut [Group], uuid: &[u8; 16]) -> Result<(), CoreError> {
        for group in groups {
            if let Some(pos) = group.entries.iter().position(|e| &e.uuid == uuid) {
                group.entries.remove(pos);
                return Ok(());
            }
            Self::delete_entry_in_groups(&mut group.children, uuid)?;
        }
        Ok(())
    }

    pub fn create_group(&self, parent_uuid: Option<&[u8; 16]>, name: &str) -> Result<[u8; 16], CoreError> {
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
            let parent_group = session.find_group_mut(parent).ok_or(CoreError::GroupNotFound)?;
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
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EntrySummary {
    pub uuid: [u8; 16],
    pub title: Zeroizing<String>,
    pub username: Zeroizing<String>,
    pub url: Zeroizing<String>,
    pub has_totp: bool,
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
        manager.update_entry(&entry.uuid, Some("GitHub Updated".into()), None, None, None, None, None).unwrap();

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
