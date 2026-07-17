use crate::binary_utils::{
    checked_add, find_zip_eocd_locator, read_le16 as read_binary_le16,
    read_le32 as read_binary_le32, zip_central_directory_record_size,
};
use crate::types::{ArchiveMetadata, EXTENSION_LIST, FileType};
use crc32fast::Hasher;
use flate2::{Decompress, FlushDecompress, Status};

pub type ArchiveResult<T> = Result<T, String>;

const WRAP_PREFIX_SIZE: usize = 8;
const WRAP_TRAILER_SIZE: usize = 4;
const LOCAL_RECORD_MIN_SIZE: usize = 30;
const LOCAL_RECORD_NAME_INDEX: usize = 30;
const CENTRAL_RECORD_MIN_SIZE: usize = 46;
const CENTRAL_RECORD_NAME_INDEX: usize = 46;
const MAX_TOTAL_UNCOMPRESSED_SIZE: u64 = 2 * 1024 * 1024 * 1024;
// The byte-per-node path trie is deliberately capped independently of archive
// size. This bounds its worst-case allocation even when an archive contains
// many long, non-sharing names.
const MAX_TOTAL_NORMALIZED_PATH_BYTES: usize = 4 * 1024 * 1024;

const ZIP_LOCAL_SIG: [u8; 4] = *b"PK\x03\x04";
const CENTRAL_SIG: [u8; 4] = *b"PK\x01\x02";
const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;

const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_EXTENDED_LANGUAGE: u16 = 0x0008;
const EXTRA_INFOZIP_UNICODE_PATH: u16 = 0x7075;

fn read_le16(data: &[u8], offset: usize, context: &str) -> ArchiveResult<u16> {
    read_binary_le16(data, offset).map_err(|_| format!("{context}: Truncated ZIP record."))
}

fn read_le32(data: &[u8], offset: usize, context: &str) -> ArchiveResult<u32> {
    read_binary_le32(data, offset).map_err(|_| format!("{context}: Truncated ZIP record."))
}

fn checked_slice<'a>(
    data: &'a [u8],
    start: usize,
    length: usize,
    overflow_error: &str,
    bounds_error: &str,
) -> ArchiveResult<&'a [u8]> {
    let end = checked_add(start, length, overflow_error)?;
    data.get(start..end).ok_or_else(|| bounds_error.to_string())
}

fn read_zip_name(data: &[u8], start: usize, length: usize) -> ArchiveResult<&[u8]> {
    checked_slice(
        data,
        start,
        length,
        "Archive File Error: ZIP filename length overflow.",
        "Archive File Error: ZIP filename exceeds archive bounds.",
    )
}

fn to_lower_ascii(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}

fn has_windows_reserved_segment_name(segment: &[u8]) -> bool {
    let stem_end = segment
        .iter()
        .position(|byte| *byte == b'.')
        .unwrap_or(segment.len());
    let stem = &segment[..stem_end];
    let equals_ascii = |expected: &[u8]| {
        stem.len() == expected.len()
            && stem
                .iter()
                .zip(expected)
                .all(|(actual, wanted)| to_lower_ascii(*actual) == *wanted)
    };

    if equals_ascii(b"con") || equals_ascii(b"prn") || equals_ascii(b"aux") || equals_ascii(b"nul")
    {
        return true;
    }

    stem.len() == 4
        && matches!(stem[3], b'1'..=b'9')
        && ((to_lower_ascii(stem[0]) == b'c'
            && to_lower_ascii(stem[1]) == b'o'
            && to_lower_ascii(stem[2]) == b'm')
            || (to_lower_ascii(stem[0]) == b'l'
                && to_lower_ascii(stem[1]) == b'p'
                && to_lower_ascii(stem[2]) == b't'))
}

fn has_windows_invalid_path_character(segment: &[u8]) -> bool {
    segment
        .iter()
        .any(|byte| matches!(*byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'))
}

fn is_unsafe_entry_path(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.contains(&b'\\') || bytes[0] == b'/' {
        return true;
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }

    let mut segment_start = 0usize;
    for index in 0..=bytes.len() {
        if index < bytes.len() && bytes[index] != b'/' {
            continue;
        }

        let segment = &bytes[segment_start..index];
        let trailing_directory_separator = index == bytes.len() && segment.is_empty();
        if !trailing_directory_separator
            && (segment.is_empty()
                || segment == b"."
                || segment == b".."
                || matches!(segment.last(), Some(b'.' | b' '))
                || has_windows_invalid_path_character(segment)
                || has_windows_reserved_segment_name(segment))
        {
            return true;
        }
        segment_start = index + 1;
    }

    false
}

fn display_zip_name(entry_name: &[u8]) -> String {
    String::from_utf8_lossy(entry_name).into_owned()
}

fn validate_entry_name(
    entry_name: &[u8],
    location: &str,
    entry_number: usize,
) -> ArchiveResult<()> {
    if entry_name.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        return Err(format!(
            "Archive File Error: {location} entry {entry_number} contains unsupported control characters."
        ));
    }
    if is_unsafe_entry_path(entry_name) {
        let display_name = display_zip_name(entry_name);
        return Err(format!(
            "Archive Security Error: Unsafe {location} archive entry path detected: \"{display_name}\"."
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct LocalEntrySpan {
    begin: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy)]
struct CentralDirectoryBounds {
    start: usize,
    end: usize,
    total_records: u16,
}

#[derive(Debug, Clone, Copy)]
struct CentralEntryMetadata<'a> {
    entry_number: usize,
    version_made_by: u16,
    flags: u16,
    compression_method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    disk_start: u16,
    external_attributes: u32,
    local_header_offset: usize,
    name: &'a [u8],
    extra: &'a [u8],
    record_size: usize,
}

const NO_PATH_NODE: u32 = u32::MAX;

#[derive(Debug)]
struct PathNode {
    first_child: u32,
    next_sibling: u32,
    label: u8,
    has_explicit_entry: bool,
    is_file: bool,
    is_directory: bool,
}

impl Default for PathNode {
    fn default() -> Self {
        Self {
            first_child: NO_PATH_NODE,
            next_sibling: NO_PATH_NODE,
            label: 0,
            has_explicit_entry: false,
            is_file: false,
            is_directory: false,
        }
    }
}

#[derive(Debug)]
struct PortablePathTrie {
    nodes: Vec<PathNode>,
    total_normalized_path_bytes: usize,
}

impl PortablePathTrie {
    fn with_entry_capacity(entry_count: usize) -> ArchiveResult<Self> {
        let initial_capacity = entry_count
            .checked_add(1)
            .ok_or_else(|| "Archive Security Error: Path-trie capacity overflow.".to_string())?;
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(initial_capacity).map_err(|_| {
            "Archive Security Error: Unable to allocate archive path validation state.".to_string()
        })?;
        nodes.push(PathNode::default());
        Ok(Self {
            nodes,
            total_normalized_path_bytes: 0,
        })
    }

    fn find_or_add_child(&mut self, parent: usize, label: u8) -> ArchiveResult<usize> {
        let mut child = self.nodes[parent].first_child;
        while child != NO_PATH_NODE {
            let index = child as usize;
            if self.nodes[index].label == label {
                return Ok(index);
            }
            child = self.nodes[index].next_sibling;
        }

        let index = self.nodes.len();
        let encoded_index = u32::try_from(index).map_err(|_| {
            "Archive Security Error: Archive path validation state exceeds its safety limit."
                .to_string()
        })?;
        let next_sibling = self.nodes[parent].first_child;
        self.nodes.try_reserve(1).map_err(|_| {
            "Archive Security Error: Unable to grow archive path validation state.".to_string()
        })?;
        self.nodes.push(PathNode {
            next_sibling,
            label,
            ..PathNode::default()
        });
        self.nodes[parent].first_child = encoded_index;
        Ok(index)
    }

    fn insert(&mut self, entry_name: &[u8], entry_number: usize) -> ArchiveResult<()> {
        let is_directory_entry = entry_name.ends_with(b"/");
        let key_size = entry_name.len() - usize::from(is_directory_entry);
        if key_size == 0 {
            return Err(format!(
                "Archive Security Error: Empty normalized path for archive entry {entry_number}."
            ));
        }
        let new_total = self
            .total_normalized_path_bytes
            .checked_add(key_size)
            .ok_or_else(|| {
                "Archive Security Error: Aggregate normalized archive path size overflow."
                    .to_string()
            })?;
        if new_total > MAX_TOTAL_NORMALIZED_PATH_BYTES {
            return Err(
                "Archive Security Error: Aggregate normalized archive path size exceeds the safety limit."
                    .to_string(),
            );
        }
        self.total_normalized_path_bytes = new_total;

        let mut node = 0usize;
        for byte in &entry_name[..key_size] {
            if *byte == b'/' {
                if self.nodes[node].is_file {
                    return Err(format!(
                        "Archive Security Error: Archive entry {entry_number} conflicts with an existing file path."
                    ));
                }
                self.nodes[node].is_directory = true;
            }
            let normalized = if *byte == b'\\' {
                b'/'
            } else {
                to_lower_ascii(*byte)
            };
            node = self.find_or_add_child(node, normalized)?;
        }

        if self.nodes[node].has_explicit_entry {
            let display_name = display_zip_name(entry_name);
            return Err(format!(
                "Archive Security Error: Duplicate or case-conflicting archive entry path detected: \"{display_name}\"."
            ));
        }

        if is_directory_entry {
            if self.nodes[node].is_file {
                return Err(format!(
                    "Archive Security Error: Directory entry {entry_number} conflicts with an existing file path."
                ));
            }
            self.nodes[node].is_directory = true;
        } else {
            if self.nodes[node].is_directory {
                return Err(format!(
                    "Archive Security Error: File entry {entry_number} conflicts with an existing directory path."
                ));
            }
            self.nodes[node].is_file = true;
        }
        self.nodes[node].has_explicit_entry = true;
        Ok(())
    }
}

#[derive(Debug)]
struct ArchiveEntryTracking {
    total_declared_uncompressed: u64,
    total_verified_uncompressed: u64,
    paths: PortablePathTrie,
    local_spans: Vec<LocalEntrySpan>,
}

impl ArchiveEntryTracking {
    fn new(total_records: u16) -> ArchiveResult<Self> {
        let capacity = usize::from(total_records);
        let mut local_spans = Vec::new();
        local_spans.try_reserve_exact(capacity).map_err(|_| {
            "Archive Security Error: Unable to allocate local-entry validation state.".to_string()
        })?;
        Ok(Self {
            total_declared_uncompressed: 0,
            total_verified_uncompressed: 0,
            paths: PortablePathTrie::with_entry_capacity(capacity)?,
            local_spans,
        })
    }
}

fn validate_zip_extra_fields(
    extra: &[u8],
    location: &str,
    entry_number: usize,
) -> ArchiveResult<()> {
    let mut cursor = 0usize;
    while cursor < extra.len() {
        if extra.len() - cursor < 4 {
            return Err(format!(
                "Archive File Error: Malformed {location} extra field on entry {entry_number}."
            ));
        }

        let field_id = read_le16(extra, cursor, "Archive File Error")?;
        let field_size = usize::from(read_le16(extra, cursor + 2, "Archive File Error")?);
        cursor += 4;
        if field_size > extra.len() - cursor {
            return Err(format!(
                "Archive File Error: Malformed {location} extra field on entry {entry_number}."
            ));
        }

        if field_id == EXTRA_ZIP64 {
            return Err(format!(
                "Archive File Error: ZIP64 extra field is not supported on entry {entry_number}."
            ));
        }
        if field_id == EXTRA_INFOZIP_UNICODE_PATH || field_id == EXTRA_EXTENDED_LANGUAGE {
            return Err(format!(
                "Archive Security Error: Path-override extra field 0x{field_id:04x} is not supported on entry {entry_number}."
            ));
        }

        cursor += field_size;
    }
    Ok(())
}

fn is_unix_like_zip_host(version_made_by: u16) -> bool {
    matches!((version_made_by >> 8) as u8, 3 | 19)
}

fn validate_entry_attributes(entry: &CentralEntryMetadata<'_>) -> ArchiveResult<()> {
    const GENERAL_PURPOSE_ENCRYPTED: u16 = 1 << 0;
    const GENERAL_PURPOSE_STRONG_ENCRYPTION: u16 = 1 << 6;
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_REGULAR_FILE: u32 = 0o100000;
    const UNIX_DIRECTORY: u32 = 0o040000;
    const UNIX_SYMLINK: u32 = 0o120000;

    if entry.flags & (GENERAL_PURPOSE_ENCRYPTED | GENERAL_PURPOSE_STRONG_ENCRYPTION) != 0 {
        return Err(format!(
            "Archive Security Error: Encrypted archive entry {} is not supported.",
            entry.entry_number
        ));
    }
    if !is_unix_like_zip_host(entry.version_made_by) {
        return Ok(());
    }

    let mode_type = (entry.external_attributes >> 16) & UNIX_FILE_TYPE_MASK;
    if mode_type == 0 {
        return Ok(());
    }
    if mode_type == UNIX_SYMLINK {
        let display_name = display_zip_name(entry.name);
        return Err(format!(
            "Archive Security Error: Symlink archive entry {} is not supported: \"{}\".",
            entry.entry_number, display_name
        ));
    }
    if mode_type != UNIX_REGULAR_FILE && mode_type != UNIX_DIRECTORY {
        let display_name = display_zip_name(entry.name);
        return Err(format!(
            "Archive Security Error: Special archive entry {} is not supported: \"{}\".",
            entry.entry_number, display_name
        ));
    }
    if mode_type == UNIX_DIRECTORY && !entry.name.ends_with(b"/") {
        return Err(format!(
            "Archive File Error: Directory metadata does not match archive entry path {}.",
            entry.entry_number
        ));
    }
    if mode_type == UNIX_REGULAR_FILE && entry.name.ends_with(b"/") {
        return Err(format!(
            "Archive File Error: File metadata does not match archive entry path {}.",
            entry.entry_number
        ));
    }
    Ok(())
}

fn validate_entry_size_metadata(
    entry: &CentralEntryMetadata<'_>,
    total_uncompressed: &mut u64,
) -> ArchiveResult<()> {
    if entry.compressed_size == u32::MAX || entry.uncompressed_size == u32::MAX {
        return Err(format!(
            "Archive File Error: ZIP64 size metadata is not supported for entry {}.",
            entry.entry_number
        ));
    }
    if entry.name.ends_with(b"/") {
        if entry.uncompressed_size != 0 {
            return Err(format!(
                "Archive File Error: Directory entry {} has non-zero uncompressed size.",
                entry.entry_number
            ));
        }
        return Ok(());
    }

    let entry_size = u64::from(entry.uncompressed_size);
    if entry_size > MAX_TOTAL_UNCOMPRESSED_SIZE
        || *total_uncompressed > MAX_TOTAL_UNCOMPRESSED_SIZE - entry_size
    {
        return Err(
            "Archive Security Error: Total uncompressed archive size exceeds the safety limit."
                .to_string(),
        );
    }
    *total_uncompressed += entry_size;
    Ok(())
}

fn validate_compression_method(method: u16, entry_number: usize) -> ArchiveResult<()> {
    if !matches!(method, 0 | 8) {
        return Err(format!(
            "Archive File Error: Unsupported ZIP compression method {method} on entry {entry_number}."
        ));
    }
    Ok(())
}

fn payload_crc32(payload: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(payload);
    hasher.finalize()
}

fn verify_deflated_payload(
    compressed: &[u8],
    expected_uncompressed_size: u32,
    expected_crc32: u32,
    output_limit: u64,
    entry_number: usize,
) -> ArchiveResult<u64> {
    let mut decompressor = Decompress::new(false);
    let mut input_offset = 0usize;
    let mut output_size = 0u64;
    let mut output = [0u8; 64 * 1024];
    let mut hasher = Hasher::new();

    loop {
        let input_before = decompressor.total_in();
        let output_before = decompressor.total_out();
        let status = decompressor
            .decompress(
                &compressed[input_offset..],
                &mut output,
                FlushDecompress::None,
            )
            .map_err(|error| {
                format!(
                    "Archive File Error: Corrupt DEFLATE stream on entry {entry_number}: {error}."
                )
            })?;

        let consumed = usize::try_from(decompressor.total_in() - input_before).map_err(|_| {
            format!("Archive File Error: DEFLATE input counter overflow on entry {entry_number}.")
        })?;
        let produced = usize::try_from(decompressor.total_out() - output_before).map_err(|_| {
            format!("Archive File Error: DEFLATE output counter overflow on entry {entry_number}.")
        })?;
        input_offset = checked_add(
            input_offset,
            consumed,
            "Archive File Error: DEFLATE input offset overflow.",
        )?;

        if output_size > output_limit || produced as u64 > output_limit - output_size {
            return Err(format!(
                "Archive Security Error: Actual output for entry {entry_number} exceeds its permitted size."
            ));
        }
        hasher.update(&output[..produced]);
        output_size += produced as u64;

        if status == Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            return Err(if input_offset == compressed.len() {
                format!("Archive File Error: Truncated DEFLATE stream on entry {entry_number}.")
            } else {
                format!("Archive File Error: Invalid DEFLATE stream on entry {entry_number}.")
            });
        }
    }

    if input_offset != compressed.len() || decompressor.total_in() != compressed.len() as u64 {
        return Err(format!(
            "Archive File Error: DEFLATE stream on entry {entry_number} has trailing compressed bytes."
        ));
    }
    if output_size != u64::from(expected_uncompressed_size)
        || decompressor.total_out() != output_size
    {
        return Err(format!(
            "Archive File Error: Actual uncompressed size differs from metadata on entry {entry_number}."
        ));
    }
    if hasher.finalize() != expected_crc32 {
        return Err(format!(
            "Archive File Error: CRC-32 verification failed on entry {entry_number}."
        ));
    }
    Ok(output_size)
}

fn verify_entry_payload(
    compression_method: u16,
    compressed: &[u8],
    expected_uncompressed_size: u32,
    expected_crc32: u32,
    total_verified_uncompressed: u64,
    entry_number: usize,
) -> ArchiveResult<u64> {
    if total_verified_uncompressed > MAX_TOTAL_UNCOMPRESSED_SIZE {
        return Err(
            "Archive Security Error: Actual uncompressed archive size exceeds the safety limit."
                .to_string(),
        );
    }
    let remaining_output = MAX_TOTAL_UNCOMPRESSED_SIZE - total_verified_uncompressed;
    let output_limit = u64::from(expected_uncompressed_size).min(remaining_output);

    if compression_method == 8 {
        return verify_deflated_payload(
            compressed,
            expected_uncompressed_size,
            expected_crc32,
            output_limit,
            entry_number,
        );
    }
    validate_compression_method(compression_method, entry_number)?;

    if compressed.len() as u64 != u64::from(expected_uncompressed_size)
        || compressed.len() as u64 > output_limit
    {
        return Err(format!(
            "Archive File Error: Stored payload size differs from metadata on entry {entry_number}."
        ));
    }
    if payload_crc32(compressed) != expected_crc32 {
        return Err(format!(
            "Archive File Error: CRC-32 verification failed on entry {entry_number}."
        ));
    }
    Ok(compressed.len() as u64)
}

fn descriptor32_matches(
    archive_data: &[u8],
    offset: usize,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
) -> bool {
    read_binary_le32(archive_data, offset).ok() == Some(crc32)
        && read_binary_le32(archive_data, offset + 4).ok() == Some(compressed_size)
        && read_binary_le32(archive_data, offset + 8).ok() == Some(uncompressed_size)
}

fn read_data_descriptor_length(
    archive_data: &[u8],
    descriptor_start: usize,
    central_start: usize,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    entry_number: usize,
) -> ArchiveResult<usize> {
    const WITHOUT_SIGNATURE_SIZE: usize = 12;
    const WITH_SIGNATURE_SIZE: usize = 16;

    if descriptor_start > central_start {
        return Err(format!(
            "Archive File Error: Compressed data for entry {entry_number} extends past the central directory."
        ));
    }
    let available = central_start - descriptor_start;
    if available >= WITH_SIGNATURE_SIZE
        && read_binary_le32(archive_data, descriptor_start).ok() == Some(DATA_DESCRIPTOR_SIG)
        && descriptor32_matches(
            archive_data,
            descriptor_start + 4,
            crc32,
            compressed_size,
            uncompressed_size,
        )
    {
        return Ok(WITH_SIGNATURE_SIZE);
    }
    if available >= WITHOUT_SIGNATURE_SIZE
        && descriptor32_matches(
            archive_data,
            descriptor_start,
            crc32,
            compressed_size,
            uncompressed_size,
        )
    {
        return Ok(WITHOUT_SIGNATURE_SIZE);
    }
    Err(format!(
        "Archive File Error: Data descriptor for entry {entry_number} is missing or inconsistent."
    ))
}

fn validate_local_entry_payload(
    archive_data: &[u8],
    local_header_start: usize,
    local_record_end: usize,
    central_start: usize,
    entry: &CentralEntryMetadata<'_>,
    total_verified_uncompressed: &mut u64,
    local_spans: &mut Vec<LocalEntrySpan>,
) -> ArchiveResult<()> {
    const GENERAL_PURPOSE_DATA_DESCRIPTOR: u16 = 1 << 3;

    let local_flags = read_le16(archive_data, local_header_start + 6, "Archive File Error")?;
    if local_flags != entry.flags {
        return Err(format!(
            "Archive File Error: Local and central ZIP flags differ for entry {}.",
            entry.entry_number
        ));
    }
    let local_method = read_le16(archive_data, local_header_start + 8, "Archive File Error")?;
    if local_method != entry.compression_method {
        return Err(format!(
            "Archive File Error: Local and central compression methods differ for entry {}.",
            entry.entry_number
        ));
    }

    let has_data_descriptor = entry.flags & GENERAL_PURPOSE_DATA_DESCRIPTOR != 0;
    let local_crc32 = read_le32(archive_data, local_header_start + 14, "Archive File Error")?;
    let local_compressed_size =
        read_le32(archive_data, local_header_start + 18, "Archive File Error")?;
    let local_uncompressed_size =
        read_le32(archive_data, local_header_start + 22, "Archive File Error")?;
    let local_metadata_matches = local_crc32 == entry.crc32
        && local_compressed_size == entry.compressed_size
        && local_uncompressed_size == entry.uncompressed_size;
    let descriptor_metadata_compatible = (local_crc32 == 0 || local_crc32 == entry.crc32)
        && (local_compressed_size == 0 || local_compressed_size == entry.compressed_size)
        && (local_uncompressed_size == 0 || local_uncompressed_size == entry.uncompressed_size);
    if (!has_data_descriptor && !local_metadata_matches)
        || (has_data_descriptor && !descriptor_metadata_compatible)
    {
        return Err(format!(
            "Archive File Error: Local and central CRC/size metadata differ for entry {}.",
            entry.entry_number
        ));
    }

    let compressed_end = checked_add(
        local_record_end,
        entry.compressed_size as usize,
        "Archive File Error: Local compressed data size overflow.",
    )?;
    if compressed_end > central_start {
        return Err(format!(
            "Archive File Error: Compressed data for entry {} extends into the central directory.",
            entry.entry_number
        ));
    }
    let compressed_payload = archive_data
        .get(local_record_end..compressed_end)
        .ok_or_else(|| {
            "Archive File Error: Compressed payload exceeds archive bounds.".to_string()
        })?;
    let verified_size = verify_entry_payload(
        entry.compression_method,
        compressed_payload,
        entry.uncompressed_size,
        entry.crc32,
        *total_verified_uncompressed,
        entry.entry_number,
    )?;
    if verified_size > MAX_TOTAL_UNCOMPRESSED_SIZE - *total_verified_uncompressed {
        return Err(
            "Archive Security Error: Actual uncompressed archive size exceeds the safety limit."
                .to_string(),
        );
    }
    *total_verified_uncompressed += verified_size;

    let mut local_payload_end = compressed_end;
    if has_data_descriptor {
        let descriptor_length = read_data_descriptor_length(
            archive_data,
            compressed_end,
            central_start,
            entry.crc32,
            entry.compressed_size,
            entry.uncompressed_size,
            entry.entry_number,
        )?;
        local_payload_end = checked_add(
            compressed_end,
            descriptor_length,
            "Archive File Error: Local data descriptor size overflow.",
        )?;
        if local_payload_end > central_start {
            return Err(format!(
                "Archive File Error: Data descriptor for entry {} extends into the central directory.",
                entry.entry_number
            ));
        }
    }

    local_spans.try_reserve(1).map_err(|_| {
        "Archive Security Error: Unable to grow local-entry validation state.".to_string()
    })?;
    local_spans.push(LocalEntrySpan {
        begin: local_header_start,
        end: local_payload_end,
    });
    Ok(())
}

fn validate_local_entry_for_central_entry(
    archive_data: &[u8],
    central_start: usize,
    entry: &CentralEntryMetadata<'_>,
    tracking: &mut ArchiveEntryTracking,
) -> ArchiveResult<()> {
    let local_header_start = checked_add(
        WRAP_PREFIX_SIZE,
        entry.local_header_offset,
        "Archive File Error: Local file header offset overflow.",
    )?;
    if local_header_start >= central_start {
        return Err(
            "Archive File Error: Local file header points inside the central directory."
                .to_string(),
        );
    }
    if local_header_start > archive_data.len()
        || LOCAL_RECORD_MIN_SIZE > archive_data.len() - local_header_start
    {
        return Err("Archive File Error: Truncated local file header.".to_string());
    }
    if archive_data.get(local_header_start..local_header_start + ZIP_LOCAL_SIG.len())
        != Some(ZIP_LOCAL_SIG.as_slice())
    {
        return Err(format!(
            "Archive File Error: Invalid local file header signature for entry {}.",
            entry.entry_number
        ));
    }

    let local_name_length = usize::from(read_le16(
        archive_data,
        local_header_start + 26,
        "Archive File Error",
    )?);
    let local_extra_length = usize::from(read_le16(
        archive_data,
        local_header_start + 28,
        "Archive File Error",
    )?);
    let local_name_start = checked_add(
        local_header_start,
        LOCAL_RECORD_NAME_INDEX,
        "Archive File Error: Local filename offset overflow.",
    )?;
    let local_extra_start = checked_add(
        local_name_start,
        local_name_length,
        "Archive File Error: Local filename length overflow.",
    )?;
    let local_record_end = checked_add(
        local_extra_start,
        local_extra_length,
        "Archive File Error: Local header extra-field length overflow.",
    )?;
    if local_record_end > archive_data.len() {
        return Err("Archive File Error: Local file header exceeds archive bounds.".to_string());
    }

    let local_name = read_zip_name(archive_data, local_name_start, local_name_length)?;
    validate_entry_name(local_name, "local", entry.entry_number)?;
    let local_extra = archive_data
        .get(local_extra_start..local_record_end)
        .ok_or_else(|| {
            "Archive File Error: Local extra field exceeds archive bounds.".to_string()
        })?;
    validate_zip_extra_fields(local_extra, "local-header", entry.entry_number)?;
    if local_name != entry.name {
        return Err(format!(
            "Archive Security Error: Local and central directory names differ for entry {}.",
            entry.entry_number
        ));
    }

    validate_local_entry_payload(
        archive_data,
        local_header_start,
        local_record_end,
        central_start,
        entry,
        &mut tracking.total_verified_uncompressed,
        &mut tracking.local_spans,
    )
}

fn validate_local_entry_spans(local_spans: &mut [LocalEntrySpan]) -> ArchiveResult<()> {
    local_spans.sort_unstable_by_key(|span| span.begin);
    for spans in local_spans.windows(2) {
        if spans[1].begin < spans[0].end {
            return Err("Archive File Error: Local ZIP entry payloads overlap.".to_string());
        }
    }
    Ok(())
}

fn find_end_of_central_directory(archive_data: &[u8]) -> ArchiveResult<usize> {
    const EOCD_MIN_SIZE: usize = 22;
    if archive_data.len() < WRAP_PREFIX_SIZE + WRAP_TRAILER_SIZE + EOCD_MIN_SIZE {
        return Err("Archive File Error: Archive is too small.".to_string());
    }
    let archive_end = archive_data.len() - WRAP_TRAILER_SIZE;
    find_zip_eocd_locator(archive_data, WRAP_PREFIX_SIZE, archive_end)
        .map(|locator| locator.index)
        .ok_or_else(|| "Archive File Error: End of central directory record not found.".to_string())
}

fn read_central_directory_bounds(
    archive_data: &[u8],
    eocd_index: usize,
) -> ArchiveResult<CentralDirectoryBounds> {
    let disk_number = read_le16(archive_data, eocd_index + 4, "Archive File Error")?;
    let central_disk = read_le16(archive_data, eocd_index + 6, "Archive File Error")?;
    let records_on_disk = read_le16(archive_data, eocd_index + 8, "Archive File Error")?;
    let total_records = read_le16(archive_data, eocd_index + 10, "Archive File Error")?;
    let central_size = read_le32(archive_data, eocd_index + 12, "Archive File Error")?;
    let central_offset = read_le32(archive_data, eocd_index + 16, "Archive File Error")?;

    if disk_number != 0 || central_disk != 0 || records_on_disk != total_records {
        return Err("Archive File Error: Multi-disk ZIP archives are not supported.".to_string());
    }
    if total_records == 0 {
        return Err(
            "Archive File Error: Archive contains no central directory entries.".to_string(),
        );
    }
    if total_records == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err("Archive File Error: ZIP64 archives are not supported.".to_string());
    }

    let central_start = checked_add(
        WRAP_PREFIX_SIZE,
        central_offset as usize,
        "Archive File Error: Central directory offset overflow.",
    )?;
    let central_end = checked_add(
        central_start,
        central_size as usize,
        "Archive File Error: Central directory size overflow.",
    )?;
    if central_start > archive_data.len()
        || central_end > archive_data.len()
        || central_end > eocd_index
    {
        return Err("Archive File Error: Central directory bounds are invalid.".to_string());
    }
    if central_end != eocd_index {
        return Err(
            "Archive File Error: Central directory does not end at the EOCD record.".to_string(),
        );
    }

    Ok(CentralDirectoryBounds {
        start: central_start,
        end: central_end,
        total_records,
    })
}

fn read_central_entry_metadata<'a>(
    archive_data: &'a [u8],
    cursor: usize,
    central_end: usize,
    entry_number: usize,
) -> ArchiveResult<CentralEntryMetadata<'a>> {
    if cursor > archive_data.len() || CENTRAL_RECORD_MIN_SIZE > archive_data.len() - cursor {
        return Err("Archive File Error: Truncated central directory file header.".to_string());
    }
    if archive_data.get(cursor..cursor + CENTRAL_SIG.len()) != Some(CENTRAL_SIG.as_slice()) {
        return Err(
            "Archive File Error: Invalid central directory file header signature.".to_string(),
        );
    }

    let version_made_by = read_le16(archive_data, cursor + 4, "Archive File Error")?;
    let flags = read_le16(archive_data, cursor + 8, "Archive File Error")?;
    let compression_method = read_le16(archive_data, cursor + 10, "Archive File Error")?;
    let crc32 = read_le32(archive_data, cursor + 16, "Archive File Error")?;
    let compressed_size = read_le32(archive_data, cursor + 20, "Archive File Error")?;
    let uncompressed_size = read_le32(archive_data, cursor + 24, "Archive File Error")?;
    let name_length = usize::from(read_le16(archive_data, cursor + 28, "Archive File Error")?);
    let extra_length = usize::from(read_le16(archive_data, cursor + 30, "Archive File Error")?);
    let comment_length = usize::from(read_le16(archive_data, cursor + 32, "Archive File Error")?);
    let disk_start = read_le16(archive_data, cursor + 34, "Archive File Error")?;
    let external_attributes = read_le32(archive_data, cursor + 38, "Archive File Error")?;
    let local_header_offset = read_le32(archive_data, cursor + 42, "Archive File Error")? as usize;
    let record_size = zip_central_directory_record_size(name_length, extra_length, comment_length)?;

    if cursor > central_end || record_size > central_end - cursor {
        return Err(
            "Archive File Error: Central directory entry exceeds declared directory size."
                .to_string(),
        );
    }
    if record_size > archive_data.len() - cursor {
        return Err(
            "Archive File Error: Central directory entry exceeds archive bounds.".to_string(),
        );
    }

    let name_start = checked_add(
        cursor,
        CENTRAL_RECORD_NAME_INDEX,
        "Archive File Error: Central directory filename offset overflow.",
    )?;
    let name = read_zip_name(archive_data, name_start, name_length)?;
    let extra_start = checked_add(
        name_start,
        name_length,
        "Archive File Error: Central directory extra-field offset overflow.",
    )?;
    let extra_end = checked_add(
        extra_start,
        extra_length,
        "Archive File Error: Central directory extra-field length overflow.",
    )?;
    let extra = archive_data.get(extra_start..extra_end).ok_or_else(|| {
        "Archive File Error: Central directory extra field exceeds archive bounds.".to_string()
    })?;

    Ok(CentralEntryMetadata {
        entry_number,
        version_made_by,
        flags,
        compression_method,
        crc32,
        compressed_size,
        uncompressed_size,
        disk_start,
        external_attributes,
        local_header_offset,
        name,
        extra,
        record_size,
    })
}

fn validate_central_entry_metadata(
    entry: &CentralEntryMetadata<'_>,
    tracking: &mut ArchiveEntryTracking,
) -> ArchiveResult<()> {
    if entry.disk_start != 0 {
        return Err(format!(
            "Archive File Error: Multi-disk local header reference on entry {} is not supported.",
            entry.entry_number
        ));
    }
    if entry.local_header_offset == u32::MAX as usize {
        return Err(format!(
            "Archive File Error: ZIP64 local-header offset is not supported on entry {}.",
            entry.entry_number
        ));
    }

    validate_entry_name(entry.name, "central-directory", entry.entry_number)?;
    validate_zip_extra_fields(entry.extra, "central-directory", entry.entry_number)?;
    validate_compression_method(entry.compression_method, entry.entry_number)?;
    validate_entry_attributes(entry)?;
    validate_entry_size_metadata(entry, &mut tracking.total_declared_uncompressed)?;
    tracking.paths.insert(entry.name, entry.entry_number)
}

#[derive(Debug)]
struct ValidatedArchiveSummary<'a> {
    first_referenced_filename: &'a [u8],
    first_referenced_local_offset: usize,
    has_jar_manifest_file: bool,
}

fn is_regular_file_entry(entry: &CentralEntryMetadata<'_>) -> bool {
    if entry.name.ends_with(b"/") {
        return false;
    }
    if is_unix_like_zip_host(entry.version_made_by) {
        const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
        const UNIX_REGULAR_FILE: u32 = 0o100000;
        let mode_type = (entry.external_attributes >> 16) & UNIX_FILE_TYPE_MASK;
        return mode_type == 0 || mode_type == UNIX_REGULAR_FILE;
    }
    const DOS_DIRECTORY_ATTRIBUTE: u32 = 0x10;
    entry.external_attributes & DOS_DIRECTORY_ATTRIBUTE == 0
}

fn validate_and_summarize_archive(
    archive_data: &[u8],
) -> ArchiveResult<ValidatedArchiveSummary<'_>> {
    let eocd_index = find_end_of_central_directory(archive_data)?;
    let central = read_central_directory_bounds(archive_data, eocd_index)?;
    let mut tracking = ArchiveEntryTracking::new(central.total_records)?;
    let mut summary = ValidatedArchiveSummary {
        first_referenced_filename: &[],
        first_referenced_local_offset: usize::MAX,
        has_jar_manifest_file: false,
    };

    let mut cursor = central.start;
    for record_index in 0..central.total_records {
        let entry = read_central_entry_metadata(
            archive_data,
            cursor,
            central.end,
            usize::from(record_index) + 1,
        )?;
        validate_central_entry_metadata(&entry, &mut tracking)?;
        validate_local_entry_for_central_entry(archive_data, central.start, &entry, &mut tracking)?;

        if entry.local_header_offset < summary.first_referenced_local_offset {
            summary.first_referenced_local_offset = entry.local_header_offset;
            summary.first_referenced_filename = entry.name;
        }
        if entry.name == b"META-INF/MANIFEST.MF" && is_regular_file_entry(&entry) {
            summary.has_jar_manifest_file = true;
        }

        cursor = checked_add(
            cursor,
            entry.record_size,
            "Archive File Error: Central directory cursor overflow.",
        )?;
    }

    if cursor != central.end {
        return Err(
            "Archive File Error: Central directory size does not match parsed records.".to_string(),
        );
    }
    if tracking.total_verified_uncompressed != tracking.total_declared_uncompressed {
        return Err(
            "Archive File Error: Verified archive size differs from declared metadata.".to_string(),
        );
    }
    validate_local_entry_spans(&mut tracking.local_spans)?;
    if summary.first_referenced_filename.is_empty() {
        return Err("Archive File Error: No referenced local ZIP entry was found.".to_string());
    }
    Ok(summary)
}

fn file_type_from_extension_index(index: usize) -> FileType {
    if index <= FileType::VideoAudio as usize {
        return FileType::VideoAudio;
    }
    match index {
        30 => FileType::Pdf,
        31 => FileType::Python,
        32 => FileType::Powershell,
        33 => FileType::BashShell,
        34 => FileType::WindowsExecutable,
        _ => FileType::UnknownFileType,
    }
}

fn classify_zip_filename(filename: &[u8]) -> ArchiveResult<FileType> {
    const FIRST_FILENAME_MIN_LENGTH: usize = 4;
    if filename.len() < FIRST_FILENAME_MIN_LENGTH {
        return Err(
            "File Error:\n\nName length of first file within archive is too short.\nIncrease length (minimum 4 characters). Make sure it has a valid extension."
                .to_string(),
        );
    }

    let is_folder = filename.ends_with(b"/");
    let Some(dot_position) = filename.iter().rposition(|byte| *byte == b'.') else {
        return Ok(if is_folder {
            FileType::Folder
        } else {
            FileType::LinuxExecutable
        });
    };

    if is_folder {
        if filename[filename.len() - 2] == b'.' {
            return Err("ZIP File Error: Invalid folder name within ZIP archive.".to_string());
        }
        return Ok(FileType::Folder);
    }

    let extension = &filename[dot_position + 1..];
    for (index, known_extension) in EXTENSION_LIST.iter().enumerate() {
        if extension.eq_ignore_ascii_case(known_extension.as_bytes()) {
            return Ok(file_type_from_extension_index(index));
        }
    }
    Ok(FileType::UnknownFileType)
}

fn copy_zip_filename(filename: &[u8]) -> ArchiveResult<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(filename.len()).map_err(|_| {
        "Archive Security Error: Unable to allocate ZIP filename metadata.".to_string()
    })?;
    copy.extend_from_slice(filename);
    Ok(copy)
}

pub fn analyze_archive(archive_data: &[u8], is_zip_file: bool) -> ArchiveResult<ArchiveMetadata> {
    let summary = validate_and_summarize_archive(archive_data)?;
    let file_type = if is_zip_file {
        classify_zip_filename(summary.first_referenced_filename)?
    } else {
        if !summary.has_jar_manifest_file {
            return Err(
                "File Type Error: Archive does not appear to be a valid JAR file.".to_string(),
            );
        }
        FileType::Jar
    };

    Ok(ArchiveMetadata {
        file_type,
        first_filename: copy_zip_filename(summary.first_referenced_filename)?,
    })
}

pub fn determine_file_type(archive_data: &[u8], is_zip_file: bool) -> ArchiveResult<FileType> {
    analyze_archive(archive_data, is_zip_file).map(|metadata| metadata.file_type)
}

pub fn get_archive_first_filename(archive_data: &[u8]) -> ArchiveResult<Vec<u8>> {
    let summary = validate_and_summarize_archive(archive_data)?;
    copy_zip_filename(summary.first_referenced_filename)
}

pub fn validate_archive_entry_paths(archive_data: &[u8]) -> ArchiveResult<()> {
    validate_and_summarize_archive(archive_data).map(|_| ())
}

pub fn to_lowercase(value: &str) -> String {
    value.to_ascii_lowercase()
}
