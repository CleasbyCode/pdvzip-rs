#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Big,
    Little,
}

pub type BinResult<T> = Result<T, String>;

// ZIP record layout shared by archive validation and polyglot assembly.
pub const ZIP_EOCD_MIN_SIZE: usize = 22;
pub const ZIP_EOCD_CENTRAL_OFFSET: usize = 16;
pub const ZIP_EOCD_COMMENT_LENGTH_OFFSET: usize = 20;
pub const ZIP64_LOCATOR_SIZE: usize = 20;
pub const ZIP_CENTRAL_RECORD_MIN_SIZE: usize = 46;
pub const ZIP_CENTRAL_RECORD_NAME_INDEX: usize = 46;
pub const ZIP_CENTRAL_FLAGS_OFFSET: usize = 8;
pub const ZIP_CENTRAL_COMPRESSION_METHOD: usize = 10;
pub const ZIP_CENTRAL_CRC32: usize = 16;
pub const ZIP_CENTRAL_COMPRESSED_SIZE: usize = 20;
pub const ZIP_CENTRAL_UNCOMPRESSED_SIZE: usize = 24;
pub const ZIP_CENTRAL_NAME_LENGTH_OFFSET: usize = 28;
pub const ZIP_CENTRAL_EXTRA_LENGTH_OFFSET: usize = 30;
pub const ZIP_CENTRAL_COMMENT_LENGTH_OFFSET: usize = 32;
pub const ZIP_CENTRAL_DISK_START: usize = 34;
pub const ZIP_CENTRAL_EXTERNAL_ATTRIBUTES: usize = 38;
pub const ZIP_CENTRAL_LOCAL_OFFSET: usize = 42;

// Bytes that can start comments or break bash or CMD parsing before execution
// reaches the extraction script; they must not appear in IHDR width/height/CRC
// or the iCCP length LSB that bash (Linux) or CMD (Windows) may skim while
// treating the PNG as a script. (The name predates the CMD cases.)
pub const fn is_linux_problem_metacharacter(value: u8) -> bool {
    // b'\n' (0x0A): bash strips NUL then splits the line here, so a line feed
    // in an IHDR field or the iCCP length byte would move the bytes after it
    // into command position before the extraction script runs.
    // b'\r' (0x0D): the Windows stub puts its REM after a bare CR; refused in
    // case CMD breaks the header line at one, which would move the bytes after
    // it into command position.
    // 0x1A (Ctrl-Z): CMD reads it as a line feed in a batch file.
    matches!(
        value,
        b'\n'
            | b'\r'
            | 0x1A
            | b'"'
            | b'#'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b';'
            | b'<'
            | b'>'
            | b'`'
            | b'|'
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

/// Neutralizes terminal controls in untrusted text before it is embedded in a
/// diagnostic, so a crafted filename, archive entry name or argv[0] cannot
/// inject escape sequences via stderr: C0 controls (ESC among them), DEL, and
/// the C1 controls U+0080..U+009F (U+009B is CSI and U+009D is OSC, the same as
/// ESC [ and ESC ]). Other characters are kept so non-ASCII names still display.
/// Callers turn raw bytes into text with from_utf8_lossy, so invalid bytes,
/// including bare 0x80..0x9F, are already U+FFFD.
pub fn sanitize_for_display(text: &str) -> String {
    text.chars()
        .map(|ch| {
            let code = ch as u32;
            if code < 0x20 || code == 0x7f || (0x80..=0x9f).contains(&code) {
                '?'
            } else {
                ch
            }
        })
        .collect()
}

/// sanitize_for_display for a whole diagnostic, keeping the line breaks that
/// multi-line messages use. Applied where errors are printed, so a message
/// that embeds untrusted text without sanitizing it is still safe.
pub fn sanitize_message_for_display(message: &str) -> String {
    message
        .split('\n')
        .map(sanitize_for_display)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn zip_central_directory_record_size(
    name_length: usize,
    extra_length: usize,
    comment_length: usize,
) -> BinResult<usize> {
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
        ZIP_CENTRAL_RECORD_MIN_SIZE,
        variable_size,
        "Archive File Error: Central directory record size overflow.",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZipEocdLocator {
    index: usize,
    comment_length: u16,
}

/// Returns the EOCD record whose comment ends exactly at `archive_end`. Fails if
/// another EOCD signature follows it or a ZIP64 locator precedes it, since
/// extractors could then select a different central directory.
fn find_zip_eocd_locator(
    data: &[u8],
    archive_begin: usize,
    archive_end: usize,
) -> BinResult<Option<ZipEocdLocator>> {
    const EOCD_MIN_SIZE: usize = ZIP_EOCD_MIN_SIZE;
    const EOCD_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
    const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = *b"PK\x06\x07";
    const MAX_EOCD_SEARCH_DISTANCE: usize = EOCD_MIN_SIZE + u16::MAX as usize;

    if archive_end > data.len()
        || archive_end < archive_begin
        || archive_end - archive_begin < EOCD_MIN_SIZE
    {
        return Ok(None);
    }

    let distance_floor = archive_end.saturating_sub(MAX_EOCD_SEARCH_DISTANCE);
    let search_floor = archive_begin.max(distance_floor);
    let mut position = archive_end - EOCD_SIGNATURE.len();
    if position < search_floor {
        return Ok(None);
    }

    // Extractors disagree on which EOCD to use when more than one signature is
    // present: Info-ZIP takes the last one in the file even if its comment
    // length does not reach the archive end. A signature after the selected
    // record could therefore point those extractors at a different, unvalidated
    // central directory, so treat it as an error rather than skipping it.
    let mut found_later_signature = false;
    loop {
        if data[position..position + EOCD_SIGNATURE.len()] == EOCD_SIGNATURE {
            if position + EOCD_MIN_SIZE <= archive_end
                && usize::from(read_le16(data, position + ZIP_EOCD_COMMENT_LENGTH_OFFSET)?)
                    == archive_end - position - EOCD_MIN_SIZE
            {
                if found_later_signature {
                    return Err("Archive Security Error: Archive comment contains an end-of-central-directory signature."
                        .to_string());
                }
                // Info-ZIP, 7-Zip and libarchive switch to ZIP64 when a ZIP64
                // locator immediately precedes the EOCD. Those bytes lie inside
                // the last central record, so a crafted record could redirect them.
                if position >= archive_begin + ZIP64_LOCATOR_SIZE
                    && data[position - ZIP64_LOCATOR_SIZE..position - ZIP64_LOCATOR_SIZE + 4]
                        == ZIP64_LOCATOR_SIGNATURE
                {
                    return Err(
                        "Archive Security Error: ZIP64 locator signature precedes the EOCD record.".to_string(),
                    );
                }
                return Ok(Some(ZipEocdLocator {
                    index: position,
                    comment_length: (archive_end - position - EOCD_MIN_SIZE) as u16,
                }));
            }
            found_later_signature = true;
        }

        if position == search_floor {
            break;
        }
        position -= 1;
    }

    Ok(None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipCentralDirectory {
    pub eocd_index: usize,
    pub eocd_comment_length: u16,
    pub total_records: u16,
    /// First central record; offsets are positions in the data.
    pub start: usize,
    /// Equal to `eocd_index`.
    pub end: usize,
}

/// Finds the EOCD of the ZIP data in `data[zip_begin..zip_end]` and validates
/// it: one disk, no ZIP64 markers, at least one record, and a central directory
/// that ends exactly at the EOCD. Error messages start with `error_prefix`.
pub fn read_zip_central_directory(
    data: &[u8],
    zip_begin: usize,
    zip_end: usize,
    error_prefix: &str,
) -> BinResult<ZipCentralDirectory> {
    const EOCD_DISK_NUMBER_OFFSET: usize = 4;
    const EOCD_CENTRAL_DISK_OFFSET: usize = 6;
    const EOCD_RECORDS_ON_DISK: usize = 8;
    const EOCD_TOTAL_RECORDS_OFFSET: usize = 10;
    const EOCD_CENTRAL_SIZE_OFFSET: usize = 12;
    let fail = |message: &str| format!("{error_prefix}: {message}");

    if zip_end > data.len() || zip_end < zip_begin || zip_end - zip_begin < ZIP_EOCD_MIN_SIZE {
        return Err(fail("Archive is too small."));
    }
    let locator = find_zip_eocd_locator(data, zip_begin, zip_end)?
        .ok_or_else(|| fail("End of central directory record not found."))?;

    let eocd = locator.index;
    let field16 = |offset: usize| read_le16(data, eocd + offset).map_err(|err| fail(&err));
    let field32 = |offset: usize| read_le32(data, eocd + offset).map_err(|err| fail(&err));
    let total_records = field16(EOCD_TOTAL_RECORDS_OFFSET)?;
    let central_size = field32(EOCD_CENTRAL_SIZE_OFFSET)?;
    let central_offset = field32(ZIP_EOCD_CENTRAL_OFFSET)?;
    if field16(EOCD_DISK_NUMBER_OFFSET)? != 0
        || field16(EOCD_CENTRAL_DISK_OFFSET)? != 0
        || field16(EOCD_RECORDS_ON_DISK)? != total_records
    {
        return Err(fail("Multi-disk ZIP archives are not supported."));
    }
    if total_records == 0 {
        return Err(fail("Archive contains no central directory entries."));
    }
    if total_records == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err(fail("ZIP64 archives are not supported."));
    }

    let central_start = zip_begin
        .checked_add(central_offset as usize)
        .ok_or_else(|| fail("Central directory offset overflow."))?;
    let central_end = central_start
        .checked_add(central_size as usize)
        .ok_or_else(|| fail("Central directory size overflow."))?;
    if central_end > eocd {
        return Err(fail("Central directory bounds are invalid."));
    }
    if central_end != eocd {
        return Err(fail("Central directory does not end at the EOCD record."));
    }
    Ok(ZipCentralDirectory {
        eocd_index: eocd,
        eocd_comment_length: locator.comment_length,
        total_records,
        start: central_start,
        end: central_end,
    })
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
        ByteOrder, find_zip_eocd_locator, get_value, is_linux_problem_metacharacter, read_value_at,
        sanitize_for_display,
        sanitize_message_for_display, search_sig, update_value, write_value_at,
        zip_central_directory_record_size,
    };

    #[test]
    fn header_problem_bytes_cover_windows_line_breaks() {
        // CMD as well as bash skims the PNG header as script text: a bare CR
        // (in case CMD breaks the line there) and Ctrl-Z (which CMD reads as a
        // line feed) are refused alongside bash's line feed.
        for value in [b'\n', b'\r', 0x1A] {
            assert!(is_linux_problem_metacharacter(value), "0x{value:02X}");
        }
    }

    #[test]
    fn display_sanitizing_neutralizes_c0_and_c1_controls() {
        let cases = [
            ("a\u{1b}[2Jb", "a?[2Jb"),
            ("\u{9b}2J", "?2J"),
            ("\u{9d}0;title\u{7}", "?0;title?"),
            ("\u{80}\u{9f}", "??"),
            ("del\u{7f}", "del?"),
            ("caf\u{e9} \u{20ac} \u{65e5}\u{1f642}", "caf\u{e9} \u{20ac} \u{65e5}\u{1f642}"),
            ("\u{a0}nbsp", "\u{a0}nbsp"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize_for_display(input), expected, "{input:?}");
        }
        for code in (0u32..0x110000).filter_map(char::from_u32) {
            let shown = sanitize_for_display(&code.to_string());
            assert!(
                !shown.chars().any(|ch| {
                    let value = ch as u32;
                    value < 0x20 || value == 0x7f || (0x80..=0x9f).contains(&value)
                }),
                "U+{:04X}",
                code as u32
            );
        }
        assert_eq!(
            sanitize_message_for_display("line one\n\u{9b}2J\r\nline three"),
            "line one\n?2J?\nline three"
        );
    }

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
        for byte in *b"\n\"#$&'();<>`|" {
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
            Ok(Some(super::ZipEocdLocator {
                index: 0,
                comment_length: 0,
            }))
        );

        archive.extend_from_slice(b"trailing");
        assert_eq!(find_zip_eocd_locator(&archive, 0, archive.len()), Ok(None));
    }

    #[test]
    fn eocd_locator_rejects_later_signatures_and_zip64_locators() {
        // A second EOCD hidden in the comment of the real one.
        let mut archive = vec![0u8; 22];
        archive[0..4].copy_from_slice(b"PK\x05\x06");
        let comment = [b"PK\x05\x06".as_slice(), &[0u8; 18], b"padding"].concat();
        archive[20..22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        archive.extend_from_slice(&comment);
        let err = find_zip_eocd_locator(&archive, 0, archive.len()).unwrap_err();
        assert!(err.contains("end-of-central-directory signature"), "{err}");

        // A ZIP64 locator directly before the EOCD.
        let mut archive = vec![0u8; 42];
        archive[0..4].copy_from_slice(b"PK\x06\x07");
        archive[20..24].copy_from_slice(b"PK\x05\x06");
        let err = find_zip_eocd_locator(&archive, 0, archive.len()).unwrap_err();
        assert!(err.contains("ZIP64 locator"), "{err}");
    }
}
