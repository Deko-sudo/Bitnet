#[cfg(test)]
mod fuzz_tests {
    use crate::{load_vault, save_vault, Entry, Group, KdbxError};
    use rand::RngCore;

    fn try_load(data: &[u8], password: &[u8]) -> Result<Vec<Group>, KdbxError> {
        let path = std::env::temp_dir().join("fuzz_temp_test.bitnet");
        std::fs::write(&path, data).map_err(KdbxError::Io)?;
        let result = load_vault(path.to_str().unwrap(), password);
        let _ = std::fs::remove_file(&path);
        result
    }

    fn make_small_vault() -> Vec<u8> {
        let entry = Entry {
            uuid: [1u8; 16],
            title: zeroize::Zeroizing::new("T".to_string()),
            username: zeroize::Zeroizing::new("U".to_string()),
            password: zeroize::Zeroizing::new("P".to_string()),
            url: zeroize::Zeroizing::new("".to_string()),
            notes: zeroize::Zeroizing::new("".to_string()),
            totp_secret: None,
            totp_digits: None,
            totp_period: None,
            created_at: 0,
            updated_at: 0,
            accessed_at: 0,
        };
        let group = Group {
            uuid: [0u8; 16],
            name: zeroize::Zeroizing::new("R".to_string()),
            children: vec![],
            entries: vec![entry],
        };
        let path = std::env::temp_dir().join("fuzz_small.bitnet");
        save_vault(path.to_str().unwrap(), &[group], b"p").unwrap();
        let data = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        data
    }

    #[test]
    fn fuzz_random_bytes_no_panic() {
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            let len = (rng.next_u32() as usize % 2048).max(1);
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);
            let _ = try_load(&data, b"p");
        }
    }

    #[test]
    fn fuzz_truncated_valid_vault() {
        let valid = make_small_vault();
        for truncate_at in (1..valid.len()).step_by(16) {
            let _ = try_load(&valid[..truncate_at], b"p");
        }
    }

    #[test]
    fn fuzz_bitflip_valid_vault() {
        let mut valid = make_small_vault();
        for i in (0..valid.len()).step_by(8) {
            valid[i] ^= 0xFF;
            let _ = try_load(&valid, b"p");
            valid[i] ^= 0xFF;
        }
    }
}
