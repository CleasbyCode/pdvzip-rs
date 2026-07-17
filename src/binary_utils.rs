#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Big,
    Little,
}

pub type BinResult<T> = Result<T, String>;

pub const fn is_linux_problem_metacharacter(value: u8) -> bool {
    matches!(
        value,
        b'"' | b'$' | b'&' | b'\'' | b'(' | b')' | b';' | b'<' | b'>' | b'`' | b'|'
    )
}

fn is_supported_field_length(length: usize) -> bool {
    matches!(length, 2 | 4)
}

fn resolve_legacy_offset(index: usize, length: usize, byte_order: ByteOrder) -> BinResult<usize> {
    if !is_supported_field_length(length) {
        return Err(format!("legacy field access: unsupported length {length}"));
    }

    match byte_order {
        ByteOrder::Big => Ok(index),
        ByteOrder::Little => index
            .checked_sub(length - 1)
            .ok_or_else(|| "little-endian field index underflow.".to_string()),
    }
}

fn validate_field_bounds(
    data_len: usize,
    offset: usize,
    length: usize,
    fn_name: &str,
) -> BinResult<()> {
    if !is_supported_field_length(length) {
        return Err(format!("{fn_name}: unsupported length {length}"));
    }
    if offset > data_len || length > (data_len - offset) {
        return Err(format!("{fn_name}: index out of bounds"));
    }
    Ok(())
}

fn max_field_value(length: usize) -> usize {
    if length == 2 {
        u16::MAX as usize
    } else {
        u32::MAX as usize
    }
}

pub fn search_sig(data: &[u8], sig: &[u8], start: usize) -> Option<usize> {
    if sig.is_empty() || start >= data.len() {
        return None;
    }
    data.get(start..)?
        .windows(sig.len())
        .position(|window| window == sig)
        .map(|offset| start + offset)
}

pub fn write_value_at(
    data: &mut [u8],
    offset: usize,
    value: usize,
    length: usize,
    byte_order: ByteOrder,
) -> BinResult<()> {
    validate_field_bounds(data.len(), offset, length, "write_value_at")?;

    if value > max_field_value(length) {
        return Err(format!(
            "write_value_at: value {value} exceeds {length}-byte field"
        ));
    }

    for i in 0..length {
        let shift = match byte_order {
            ByteOrder::Big => (length - 1 - i) * 8,
            ByteOrder::Little => i * 8,
        };
        data[offset + i] = ((value >> shift) & 0xFF) as u8;
    }

    Ok(())
}

pub fn read_value_at(
    data: &[u8],
    offset: usize,
    length: usize,
    byte_order: ByteOrder,
) -> BinResult<usize> {
    validate_field_bounds(data.len(), offset, length, "read_value_at")?;

    let mut value = 0usize;
    for i in 0..length {
        let shift = match byte_order {
            ByteOrder::Big => (length - 1 - i) * 8,
            ByteOrder::Little => i * 8,
        };
        value |= (data[offset + i] as usize) << shift;
    }
    Ok(value)
}

pub fn update_value(
    data: &mut [u8],
    index: usize,
    value: usize,
    length: usize,
    byte_order: ByteOrder,
) -> BinResult<()> {
    let write_index = resolve_legacy_offset(index, length, byte_order)?;
    write_value_at(data, write_index, value, length, byte_order)
}

pub fn get_value(
    data: &[u8],
    index: usize,
    length: usize,
    byte_order: ByteOrder,
) -> BinResult<usize> {
    let read_index = resolve_legacy_offset(index, length, byte_order)?;
    read_value_at(data, read_index, length, byte_order)
}

pub fn checked_add(lhs: usize, rhs: usize, context: &str) -> BinResult<usize> {
    lhs.checked_add(rhs).ok_or_else(|| context.to_string())
}

pub fn checked_multiply(lhs: usize, rhs: usize, context: &str) -> BinResult<usize> {
    lhs.checked_mul(rhs).ok_or_else(|| context.to_string())
}

pub fn zip_central_directory_record_size(
    name_length: usize,
    extra_length: usize,
    comment_length: usize,
) -> BinResult<usize> {
    const CENTRAL_RECORD_MIN_SIZE: usize = 46;
    let variable_size = checked_add(
        name_length,
        checked_add(
            extra_length,
            comment_length,
            "Archive File Error: Central directory metadata length overflow.",
        )?,
        "Archive File Error: Central directory metadata length overflow.",
    )?;
    checked_add(
        CENTRAL_RECORD_MIN_SIZE,
        variable_size,
        "Archive File Error: Central directory record size overflow.",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipEocdLocator {
    pub index: usize,
    pub comment_length: u16,
}

pub fn find_zip_eocd_locator(
    data: &[u8],
    archive_begin: usize,
    archive_end: usize,
) -> Option<ZipEocdLocator> {
    const EOCD_MIN_SIZE: usize = 22;
    const EOCD_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
    const EOCD_COMMENT_LENGTH_OFFSET: usize = 20;
    const MAX_EOCD_SEARCH_DISTANCE: usize = EOCD_MIN_SIZE + u16::MAX as usize;

    if archive_end > data.len()
        || archive_end < archive_begin
        || archive_end - archive_begin < EOCD_MIN_SIZE
    {
        return None;
    }

    let distance_floor = archive_end.saturating_sub(MAX_EOCD_SEARCH_DISTANCE);
    let search_floor = archive_begin.max(distance_floor);
    let mut position = archive_end.checked_sub(EOCD_SIGNATURE.len())?;
    if position < search_floor {
        return None;
    }

    loop {
        if data.get(position..position + EOCD_SIGNATURE.len()) == Some(EOCD_SIGNATURE.as_slice())
            && position.checked_add(EOCD_MIN_SIZE)? <= archive_end
        {
            let comment_length = read_le16(data, position + EOCD_COMMENT_LENGTH_OFFSET).ok()?;
            if usize::from(comment_length) == archive_end - position - EOCD_MIN_SIZE {
                return Some(ZipEocdLocator {
                    index: position,
                    comment_length,
                });
            }
        }

        if position == search_floor {
            break;
        }
        position -= 1;
    }

    None
}

pub fn read_le16(data: &[u8], offset: usize) -> BinResult<u16> {
    read_value_at(data, offset, 2, ByteOrder::Little).map(|v| v as u16)
}

pub fn read_le32(data: &[u8], offset: usize) -> BinResult<u32> {
    read_value_at(data, offset, 4, ByteOrder::Little).map(|v| v as u32)
}

pub fn write_le16(data: &mut [u8], offset: usize, value: u16) -> BinResult<()> {
    write_value_at(data, offset, usize::from(value), 2, ByteOrder::Little)
}

pub fn write_le32(data: &mut [u8], offset: usize, value: u32) -> BinResult<()> {
    write_value_at(data, offset, value as usize, 4, ByteOrder::Little)
}

#[cfg(test)]
mod tests {
    use super::{
        ByteOrder, find_zip_eocd_locator, get_value, read_value_at, search_sig, update_value,
        write_value_at, zip_central_directory_record_size,
    };

    #[test]
    fn update_and_get_value_round_trip() {
        let mut bytes = [0u8; 8];
        update_value(&mut bytes, 0, 0x1234_5678, 4, ByteOrder::Big).expect("update");
        assert_eq!(
            get_value(&bytes, 0, 4, ByteOrder::Big).expect("get"),
            0x1234_5678
        );

        update_value(&mut bytes, 7, 0xBEEF, 2, ByteOrder::Little).expect("update");
        assert_eq!(
            get_value(&bytes, 7, 2, ByteOrder::Little).expect("get"),
            0xBEEF
        );

        write_value_at(&mut bytes, 2, 0xCAFE, 2, ByteOrder::Little).expect("write");
        assert_eq!(bytes[2], 0xFE);
        assert_eq!(bytes[3], 0xCA);
        assert_eq!(
            read_value_at(&bytes, 2, 2, ByteOrder::Little).expect("read"),
            0xCAFE
        );

        write_value_at(&mut bytes, 4, 0x0102_0304, 4, ByteOrder::Big).expect("write");
        assert_eq!(&bytes[4..8], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            read_value_at(&bytes, 4, 4, ByteOrder::Big).expect("read"),
            0x0102_0304
        );
    }

    #[test]
    fn bounds_and_length_validation() {
        let mut bytes = [0u8; 2];
        let len = bytes.len();
        assert!(update_value(&mut bytes, 0, 1, 3, ByteOrder::Big).is_err());
        assert!(get_value(&bytes, 0, 3, ByteOrder::Big).is_err());
        assert!(update_value(&mut bytes, 0, 1, 2, ByteOrder::Little).is_err());
        assert!(write_value_at(&mut bytes, len, 1, 2, ByteOrder::Big).is_err());
        assert!(read_value_at(&bytes, len, 2, ByteOrder::Big).is_err());
        assert!(get_value(&bytes, usize::MAX, 2, ByteOrder::Little).is_err());
        assert!(get_value(&bytes, 0, 0, ByteOrder::Little).is_err());
        assert!(get_value(&bytes, 0, 1, ByteOrder::Little).is_err());
    }

    #[test]
    fn search_signature() {
        let data = [1u8, 2, 3, 4, 3, 4, 5];
        assert_eq!(search_sig(&data, &[3, 4], 0), Some(2));
        assert_eq!(search_sig(&data, &[3, 4], 3), Some(4));
        assert_eq!(search_sig(&data, &[9], 0), None);
    }

    #[test]
    fn central_record_size_is_checked() {
        assert_eq!(
            zip_central_directory_record_size(10, 2, 4).expect("record size"),
            62
        );
    }

    #[test]
    fn linux_problem_metacharacters_match_native_set() {
        for byte in [
            b'"', b'$', b'&', b'\'', b'(', b')', b';', b'<', b'>', b'`', b'|',
        ] {
            assert!(super::is_linux_problem_metacharacter(byte));
        }
        for byte in [b'A', b'z', b'0', b'/', b'.', b'-', b'_', 0] {
            assert!(!super::is_linux_problem_metacharacter(byte));
        }
    }

    #[test]
    fn eocd_locator_requires_exact_comment_end() {
        let mut archive = vec![0u8; 22];
        archive[0..4].copy_from_slice(b"PK\x05\x06");
        assert_eq!(
            find_zip_eocd_locator(&archive, 0, archive.len()),
            Some(super::ZipEocdLocator {
                index: 0,
                comment_length: 0,
            })
        );

        archive.extend_from_slice(b"trailing");
        assert!(find_zip_eocd_locator(&archive, 0, archive.len()).is_none());
    }
}
