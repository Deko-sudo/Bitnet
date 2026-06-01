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

    let name = deserialize_string_zeroizing(data, offset)?;

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

        let title = deserialize_string_zeroizing(data, offset)?;
        let username = deserialize_string_zeroizing(data, offset)?;
        let password = deserialize_string_zeroizing(data, offset)?;
        let url = deserialize_string_zeroizing(data, offset)?;
        let notes = deserialize_string_zeroizing(data, offset)?;

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
