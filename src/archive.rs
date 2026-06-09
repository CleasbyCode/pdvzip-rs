use crate::binary_utils::{ByteOrder, read_value_at};
use crate::types::{EXTENSION_LIST, FileType};

pub type ArchiveResult<T> = Result<T, String>;

const WRAP_PREFIX_SIZE: usize = 8;
const WRAP_TRAILER_SIZE: usize = 4;
const ZIP_LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const CENTRAL_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];

fn read_le16(data: &[u8], offset: usize, context: &str) -> ArchiveResult<u16> {
    read_value_at(data, offset, 2, ByteOrder::Little)
        .map(|value| value as u16)
        .map_err(|_| format!("{context}: Truncated ZIP record."))
}

fn read_le32(data: &[u8], offset: usize, context: &str) -> ArchiveResult<u32> {
    read_value_at(data, offset, 4, ByteOrder::Little)
        .map(|value| value as u32)
        .map_err(|_| format!("{context}: Truncated ZIP record."))
}

fn parse_first_zip_filename(archive_data: &[u8]) -> ArchiveResult<String> {
    const ZIP_LOCAL_HEADER_INDEX: usize = WRAP_PREFIX_SIZE;
    const ZIP_LOCAL_HEADER_MIN_SIZE: usize = 30;
    const FILENAME_LENGTH_INDEX: usize = ZIP_LOCAL_HEADER_INDEX + 26;
    const EXTRA_LENGTH_INDEX: usize = ZIP_LOCAL_HEADER_INDEX + 28;
    const FILENAME_INDEX: usize = ZIP_LOCAL_HEADER_INDEX + 30;
    const FIRST_FILENAME_MIN_LENGTH: usize = 4;

    if archive_data.len() < ZIP_LOCAL_HEADER_INDEX + ZIP_LOCAL_HEADER_MIN_SIZE {
        return Err("Archive File Error: ZIP header is truncated.".to_string());
    }

    if archive_data[ZIP_LOCAL_HEADER_INDEX..ZIP_LOCAL_HEADER_INDEX + ZIP_LOCAL_SIG.len()]
        != ZIP_LOCAL_SIG
    {
        return Err("Archive File Error: Missing ZIP local file header signature.".to_string());
    }

    let filename_length =
        read_le16(archive_data, FILENAME_LENGTH_INDEX, "Archive File Error")? as usize;
    let extra_length = read_le16(archive_data, EXTRA_LENGTH_INDEX, "Archive File Error")? as usize;

    if filename_length < FIRST_FILENAME_MIN_LENGTH {
        return Err(
            "File Error:\n\nName length of first file within archive is too short.\nIncrease length (minimum 4 characters). Make sure it has a valid extension.".to_string()
        );
    }

    let filename_end = FILENAME_INDEX
        .checked_add(filename_length)
        .ok_or_else(|| "Archive File Error: First filename length overflow.".to_string())?;

    if filename_end > archive_data.len() {
        return Err("Archive File Error: First filename extends past archive bounds.".to_string());
    }

    let header_end = filename_end
        .checked_add(extra_length)
        .ok_or_else(|| "Archive File Error: ZIP header length overflow.".to_string())?;

    if header_end > archive_data.len() {
        return Err(
            "Archive File Error: First ZIP header extra field extends past archive bounds."
                .to_string(),
        );
    }

    let filename_bytes = &archive_data[FILENAME_INDEX..filename_end];
    if filename_bytes.contains(&0) {
        return Err("Archive File Error: First filename contains invalid NUL bytes.".to_string());
    }

    String::from_utf8(filename_bytes.to_vec())
        .map_err(|_| "Archive File Error: First filename is not valid UTF-8.".to_string())
}

fn is_unsafe_entry_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }

    if path.starts_with('/') || path.starts_with('\\') {
        return true;
    }

    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return true;
    }

    if path.starts_with("//") || path.starts_with("\\\\") {
        return true;
    }

    path.split(['/', '\\']).any(|segment| segment == "..")
}

fn find_end_of_central_directory(archive_data: &[u8]) -> ArchiveResult<usize> {
    const EOCD_MIN_SIZE: usize = 22;

    if archive_data.len() < WRAP_PREFIX_SIZE + WRAP_TRAILER_SIZE + EOCD_MIN_SIZE {
        return Err("Archive File Error: Archive is too small.".to_string());
    }

    let search_end = archive_data.len() - WRAP_TRAILER_SIZE;
    if search_end < EOCD_SIG.len() {
        return Err("Archive File Error: End of central directory record not found.".to_string());
    }

    let min_pos = WRAP_PREFIX_SIZE;
    let mut pos = search_end - EOCD_SIG.len();

    loop {
        if pos < min_pos {
            break;
        }

        if archive_data[pos..pos + EOCD_SIG.len()] == EOCD_SIG
            && pos + EOCD_MIN_SIZE <= archive_data.len()
        {
            let comment_length = read_le16(archive_data, pos + 20, "Archive File Error")? as usize;
            let eocd_end = pos
                .checked_add(EOCD_MIN_SIZE)
                .and_then(|v| v.checked_add(comment_length))
                .ok_or_else(|| "Archive File Error: EOCD length overflow.".to_string())?;
            if eocd_end <= search_end {
                return Ok(pos);
            }
        }

        if pos == min_pos {
            break;
        }
        pos -= 1;
    }

    Err("Archive File Error: End of central directory record not found.".to_string())
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

pub fn to_lowercase(value: &str) -> String {
    value.to_ascii_lowercase()
}

pub fn determine_file_type(archive_data: &[u8], is_zip_file: bool) -> ArchiveResult<FileType> {
    let filename = parse_first_zip_filename(archive_data)?;

    if !is_zip_file {
        if filename != "META-INF/MANIFEST.MF" && filename != "META-INF/" {
            return Err(
                "File Type Error: Archive does not appear to be a valid JAR file.".to_string(),
            );
        }
        return Ok(FileType::Jar);
    }

    let last_char = filename
        .as_bytes()
        .last()
        .copied()
        .ok_or_else(|| "Archive File Error: First filename is empty.".to_string())?;

    let extension = filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_string())
        .unwrap_or_else(|| "?".to_string());

    if extension == "?" {
        return Ok(if last_char == b'/' {
            FileType::Folder
        } else {
            FileType::LinuxExecutable
        });
    }

    if last_char == b'/' {
        let bytes = filename.as_bytes();
        if bytes.len() >= 2 && bytes[bytes.len() - 2] == b'.' {
            return Err("ZIP File Error: Invalid folder name within ZIP archive.".to_string());
        }
        return Ok(FileType::Folder);
    }

    let lower_ext = to_lowercase(&extension);
    for (i, ext) in EXTENSION_LIST.iter().enumerate() {
        if *ext == lower_ext {
            return Ok(file_type_from_extension_index(i));
        }
    }

    Ok(FileType::UnknownFileType)
}

pub fn get_archive_first_filename(archive_data: &[u8]) -> ArchiveResult<String> {
    parse_first_zip_filename(archive_data)
}

pub fn validate_archive_entry_paths(archive_data: &[u8]) -> ArchiveResult<()> {
    const CENTRAL_RECORD_MIN_SIZE: usize = 46;
    const CENTRAL_RECORD_NAME_INDEX: usize = 46;

    let eocd_index = find_end_of_central_directory(archive_data)?;

    let total_records = read_le16(archive_data, eocd_index + 10, "Archive File Error")?;
    let central_size = read_le32(archive_data, eocd_index + 12, "Archive File Error")?;
    let central_offset = read_le32(archive_data, eocd_index + 16, "Archive File Error")?;

    if total_records == 0 {
        return Err(
            "Archive File Error: Archive contains no central directory entries.".to_string(),
        );
    }
    if total_records == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err("Archive File Error: ZIP64 archives are not supported.".to_string());
    }

    let central_start = WRAP_PREFIX_SIZE
        .checked_add(central_offset as usize)
        .ok_or_else(|| "Archive File Error: Central directory offset overflow.".to_string())?;
    let central_end = central_start
        .checked_add(central_size as usize)
        .ok_or_else(|| "Archive File Error: Central directory size overflow.".to_string())?;

    if central_start > archive_data.len()
        || central_end > archive_data.len()
        || central_end > eocd_index
    {
        return Err("Archive File Error: Central directory bounds are invalid.".to_string());
    }

    let mut cursor = central_start;
    for entry_idx in 0..total_records {
        if cursor > archive_data.len() || CENTRAL_RECORD_MIN_SIZE > archive_data.len() - cursor {
            return Err("Archive File Error: Truncated central directory file header.".to_string());
        }

        if archive_data[cursor..cursor + CENTRAL_SIG.len()] != CENTRAL_SIG {
            return Err(
                "Archive File Error: Invalid central directory file header signature.".to_string(),
            );
        }

        let name_length = read_le16(archive_data, cursor + 28, "Archive File Error")? as usize;
        let extra_length = read_le16(archive_data, cursor + 30, "Archive File Error")? as usize;
        let comment_length = read_le16(archive_data, cursor + 32, "Archive File Error")? as usize;

        let name_start = cursor + CENTRAL_RECORD_NAME_INDEX;
        let name_end = name_start.checked_add(name_length).ok_or_else(|| {
            "Archive File Error: Central directory filename length overflow.".to_string()
        })?;
        if name_end > archive_data.len() {
            return Err(
                "Archive File Error: Central directory filename exceeds archive bounds."
                    .to_string(),
            );
        }

        let name_bytes = &archive_data[name_start..name_end];
        if name_bytes.contains(&0) {
            return Err(format!(
                "Archive File Error: Entry {} contains invalid NUL bytes.",
                entry_idx + 1
            ));
        }

        let entry_name = String::from_utf8(name_bytes.to_vec()).map_err(|_| {
            format!(
                "Archive File Error: Entry {} filename is not valid UTF-8.",
                entry_idx + 1
            )
        })?;
        if is_unsafe_entry_path(&entry_name) {
            return Err(format!(
                "Archive Security Error: Unsafe archive entry path detected: \"{entry_name}\"."
            ));
        }

        let record_size = CENTRAL_RECORD_MIN_SIZE
            .checked_add(name_length)
            .and_then(|v| v.checked_add(extra_length))
            .and_then(|v| v.checked_add(comment_length))
            .ok_or_else(|| {
                "Archive File Error: Central directory entry size overflow.".to_string()
            })?;

        if record_size > archive_data.len() - cursor {
            return Err(
                "Archive File Error: Central directory entry exceeds archive bounds.".to_string(),
            );
        }

        cursor += record_size;
    }

    if cursor != central_end {
        return Err(
            "Archive File Error: Central directory size does not match parsed records.".to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FileType, WRAP_PREFIX_SIZE, WRAP_TRAILER_SIZE, determine_file_type,
        get_archive_first_filename, validate_archive_entry_paths,
    };

    fn write_le16(buf: &mut [u8], idx: usize, value: u16) {
        buf[idx..idx + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_le32(buf: &mut [u8], idx: usize, value: u32) {
        buf[idx..idx + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn make_wrapped_local_zip_entry(filename: &str) -> Vec<u8> {
        let mut out = vec![0u8; WRAP_PREFIX_SIZE + 30 + filename.len()];
        out[4..8].copy_from_slice(b"IDAT");
        out[WRAP_PREFIX_SIZE..WRAP_PREFIX_SIZE + 4].copy_from_slice(b"PK\x03\x04");
        write_le16(&mut out, WRAP_PREFIX_SIZE + 26, filename.len() as u16);
        out[WRAP_PREFIX_SIZE + 30..].copy_from_slice(filename.as_bytes());
        out
    }

    fn make_wrapped_zip_with_central(names: &[&str]) -> Vec<u8> {
        #[derive(Clone)]
        struct Entry {
            name: String,
            local_offset: usize,
        }

        let mut zip = Vec::<u8>::new();
        let mut entries = Vec::<Entry>::new();

        for name in names {
            let local_offset = zip.len();
            zip.resize(local_offset + 30, 0);
            zip[local_offset..local_offset + 4].copy_from_slice(b"PK\x03\x04");
            write_le16(&mut zip, local_offset + 4, 20);
            write_le16(&mut zip, local_offset + 26, name.len() as u16);
            write_le16(&mut zip, local_offset + 28, 0);
            zip.extend_from_slice(name.as_bytes());
            entries.push(Entry {
                name: (*name).to_string(),
                local_offset,
            });
        }

        let central_offset = zip.len();
        for entry in &entries {
            let start = zip.len();
            zip.resize(start + 46, 0);
            zip[start..start + 4].copy_from_slice(b"PK\x01\x02");
            write_le16(&mut zip, start + 4, 20);
            write_le16(&mut zip, start + 6, 20);
            write_le16(&mut zip, start + 28, entry.name.len() as u16);
            write_le16(&mut zip, start + 30, 0);
            write_le16(&mut zip, start + 32, 0);
            write_le32(&mut zip, start + 42, entry.local_offset as u32);
            zip.extend_from_slice(entry.name.as_bytes());
        }

        let central_size = zip.len() - central_offset;
        let eocd_start = zip.len();
        zip.resize(eocd_start + 22, 0);
        zip[eocd_start..eocd_start + 4].copy_from_slice(b"PK\x05\x06");
        write_le16(&mut zip, eocd_start + 8, entries.len() as u16);
        write_le16(&mut zip, eocd_start + 10, entries.len() as u16);
        write_le32(&mut zip, eocd_start + 12, central_size as u32);
        write_le32(&mut zip, eocd_start + 16, central_offset as u32);
        write_le16(&mut zip, eocd_start + 20, 0);

        let mut wrapped = vec![0u8; WRAP_PREFIX_SIZE];
        wrapped[4..8].copy_from_slice(b"IDAT");
        wrapped.extend_from_slice(&zip);
        wrapped.extend_from_slice(&vec![0u8; WRAP_TRAILER_SIZE]);
        wrapped
    }

    #[test]
    fn determine_type_and_first_filename() {
        let archive = make_wrapped_local_zip_entry("movie.mp4");
        assert_eq!(
            determine_file_type(&archive, true).expect("type"),
            FileType::VideoAudio
        );
        assert_eq!(
            get_archive_first_filename(&archive).expect("name"),
            "movie.mp4".to_string()
        );

        let jar_archive = make_wrapped_local_zip_entry("META-INF/MANIFEST.MF");
        assert_eq!(
            determine_file_type(&jar_archive, false).expect("jar"),
            FileType::Jar
        );

        let xvid_archive = make_wrapped_local_zip_entry("clip.xvid");
        assert_eq!(
            determine_file_type(&xvid_archive, true).expect("xvid"),
            FileType::VideoAudio
        );

        let pdf_archive = make_wrapped_local_zip_entry("doc.pdf");
        assert_eq!(
            determine_file_type(&pdf_archive, true).expect("pdf"),
            FileType::Pdf
        );

        let python_archive = make_wrapped_local_zip_entry("tool.py");
        assert_eq!(
            determine_file_type(&python_archive, true).expect("python"),
            FileType::Python
        );

        let powershell_archive = make_wrapped_local_zip_entry("tool.ps1");
        assert_eq!(
            determine_file_type(&powershell_archive, true).expect("powershell"),
            FileType::Powershell
        );

        let bash_archive = make_wrapped_local_zip_entry("tool.sh");
        assert_eq!(
            determine_file_type(&bash_archive, true).expect("bash"),
            FileType::BashShell
        );

        let exe_archive = make_wrapped_local_zip_entry("tool.exe");
        assert_eq!(
            determine_file_type(&exe_archive, true).expect("exe"),
            FileType::WindowsExecutable
        );
    }

    #[test]
    fn path_validation_rejects_unsafe_entries() {
        let safe = make_wrapped_zip_with_central(&["folder/video.mp4", "docs/readme.txt"]);
        assert!(validate_archive_entry_paths(&safe).is_ok());

        let traversal = make_wrapped_zip_with_central(&["../evil.sh"]);
        assert!(validate_archive_entry_paths(&traversal).is_err());

        let absolute = make_wrapped_zip_with_central(&["/etc/passwd"]);
        assert!(validate_archive_entry_paths(&absolute).is_err());

        let drive = make_wrapped_zip_with_central(&["C:\\Windows\\System32\\calc.exe"]);
        assert!(validate_archive_entry_paths(&drive).is_err());
    }
}
