#[cfg(test)]
mod fuzz_tests {
    use crate::{load_vault, save_vault, Entry, Group, KdbxError};
    use rand::RngCore;

    fn try_load(data: &[u8], password: &[u8]) -> Result<Vec<Group>, KdbxError> {
        let path = "fuzz_temp_test.bitnet";
        std::fs::write(path, data).map_err(|e| KdbxError::Io(e))?;
        let result = load_vault(path, password);
        let _ = std::fs::remove_file(path);
        result
    }

    fn make_small_vault() -> Vec<u8> {
        let entry = Entry {
            uuid: [1u8; 16],
            title: "T".into(),
            username: "U".into(),
            password: zeroize::Zeroizing::new("P".into()),
            url: "".into(),
            notes: "".into(),
            totp_secret: None,
        };
        let group = Group {
            uuid: [0u8; 16],
            name: "R".into(),
            children: vec![],
            entries: vec![entry],
        };
        save_vault("fuzz_small.bitnet", &[group], b"p").unwrap();
        let data = std::fs::read("fuzz_small.bitnet").unwrap();
        let _ = std::fs::remove_file("fuzz_small.bitnet");
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