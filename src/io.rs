use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type IoResult<T> = Result<T, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTypeCheck {
    CoverImage,
    ArchiveFile,
}

const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;
const IDAT_MARKER_BYTES: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x41, 0x54];
const ARCHIVE_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

pub fn has_valid_filename(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }

    let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if filename.is_empty() {
        return false;
    }

    !filename.chars().any(char::is_control)
}

pub fn has_file_extension(path: &Path, exts: &[&str]) -> bool {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    exts.iter().any(|candidate| {
        let candidate = candidate.trim_start_matches('.');
        ext.eq_ignore_ascii_case(candidate)
    })
}

pub fn read_file(path: &Path, file_type: FileTypeCheck) -> IoResult<Vec<u8>> {
    if !has_valid_filename(path) {
        return Err(
            "Invalid Input Error: Filename contains unsupported control characters.".to_string(),
        );
    }

    let metadata = fs::metadata(path).map_err(|_| {
        format!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        ));
    }

    let file_size = metadata.len();
    if file_size == 0 {
        return Err("Error: File is empty.".to_string());
    }
    let file_size = usize::try_from(file_size)
        .map_err(|_| "Error: File is too large to process on this platform.".to_string())?;

    match file_type {
        FileTypeCheck::CoverImage => {
            const MINIMUM_IMAGE_SIZE: usize = 87;
            const MAX_IMAGE_SIZE: usize = 4 * 1024 * 1024;

            if !has_file_extension(path, &[".png"]) {
                return Err(
                    "Image File Error: Invalid image extension. Only expecting \".png\"."
                        .to_string(),
                );
            }
            if file_size < MINIMUM_IMAGE_SIZE {
                return Err("Image File Error: Cover image too small. Not a valid PNG.".to_string());
            }
            if file_size > MAX_IMAGE_SIZE {
                return Err("Image File Error: Cover image exceeds the 4MB size limit.".to_string());
            }
        }
        FileTypeCheck::ArchiveFile => {
            const MAX_ARCHIVE_SIZE: usize = 2 * 1024 * 1024 * 1024;
            const MINIMUM_ARCHIVE_SIZE: usize = 30;

            if !has_file_extension(path, &[".zip", ".jar"]) {
                return Err("Archive File Error: Invalid file extension. Only expecting \".zip\" or \".jar\".".to_string());
            }
            if file_size < MINIMUM_ARCHIVE_SIZE {
                return Err("Archive File Error: Invalid file size.".to_string());
            }
            if file_size > MAX_ARCHIVE_SIZE {
                return Err("Archive File Error: File exceeds maximum size limit.".to_string());
            }
        }
    }

    let mut file = File::open(path).map_err(|err| format!("Failed to open file: {err}"))?;

    let wrap_archive = file_type == FileTypeCheck::ArchiveFile;
    let prefix_size = if wrap_archive {
        IDAT_MARKER_BYTES.len()
    } else {
        0
    };
    let buffer_size = if wrap_archive {
        file_size
            .checked_add(CHUNK_FIELDS_COMBINED_LENGTH)
            .ok_or_else(|| "Archive File Error: Wrapped archive size overflow.".to_string())?
    } else {
        file_size
    };

    let mut data = vec![0u8; buffer_size];
    if wrap_archive {
        data[..prefix_size].copy_from_slice(&IDAT_MARKER_BYTES);
    }

    file.read_exact(&mut data[prefix_size..prefix_size + file_size])
        .map_err(|_| "Failed to read full file: partial read".to_string())?;

    if wrap_archive {
        if data.len() < prefix_size + ARCHIVE_SIG.len()
            || data[prefix_size..prefix_size + ARCHIVE_SIG.len()] != ARCHIVE_SIG
        {
            return Err(
                "Archive File Error: Signature check failure. Not a valid archive file."
                    .to_string(),
            );
        }
    }

    Ok(data)
}

fn write_exact(path: &Path, bytes: &[u8], force: bool) -> IoResult<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options
        .open(path)
        .map_err(|err| format!("Write File Error: Failed to open output file: {err}"))?;
    file.write_all(bytes)
        .map_err(|err| format!("Write File Error: Failed while writing output file: {err}"))?;
    file.flush()
        .map_err(|err| format!("Write File Error: Failed while finalizing output file: {err}"))?;

    Ok(())
}

#[cfg(unix)]
fn set_output_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(0o755)) {
        eprintln!(
            "Warning: Could not set executable permissions for {} ({err}).",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn set_output_permissions(_path: &Path) {}

pub fn write_polyglot_file(
    image_data: &[u8],
    is_zip_file: bool,
    output_path: Option<&Path>,
    force: bool,
) -> IoResult<PathBuf> {
    if let Some(path) = output_path {
        if !has_valid_filename(path) {
            return Err(
                "Invalid Input Error: Filename contains unsupported control characters."
                    .to_string(),
            );
        }
        if !has_file_extension(path, &[".png"]) {
            return Err("Write File Error: Output filename must use .png extension.".to_string());
        }
        if path.exists() && !force {
            return Err(
                "Write File Error: Output file already exists. Use --force to overwrite."
                    .to_string(),
            );
        }

        write_exact(path, image_data, force)?;
        set_output_permissions(path);
        return Ok(path.to_path_buf());
    }

    const MAX_NAME_ATTEMPTS: usize = 256;
    let prefix = if is_zip_file { "pzip_" } else { "pjar_" };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut seed = now ^ (std::process::id() as u64);

    for _ in 0..MAX_NAME_ATTEMPTS {
        let number = 10_000 + (seed % 90_000);
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);

        let candidate = PathBuf::from(format!("{prefix}{number}.png"));
        if candidate.exists() {
            continue;
        }

        match write_exact(&candidate, image_data, false) {
            Ok(()) => {
                set_output_permissions(&candidate);
                return Ok(candidate);
            }
            Err(err) => {
                if candidate.exists() {
                    continue;
                }
                return Err(err);
            }
        }
    }

    Err("Write File Error: Unable to create a unique output file.".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        FileTypeCheck, has_file_extension, has_valid_filename, read_file, write_polyglot_file,
    };
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_path(stem: &str, ext: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pdvzip_rs_io_test_{stem}_{}_{}.{}",
            std::process::id(),
            id,
            ext
        ))
    }

    fn write_test_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(path, bytes).expect("write test file");
    }

    #[test]
    fn filename_and_extension_checks() {
        assert!(has_valid_filename(Path::new("face_img.png")));
        assert!(has_valid_filename(Path::new("bad name.png")));
        assert!(!has_valid_filename(Path::new("bad\nname.png")));
        assert!(has_file_extension(Path::new("A/FILE.ZIP"), &[".zip"]));
        assert!(has_file_extension(Path::new("demo.JaR"), &["zip", "jar"]));
    }

    #[test]
    fn archive_read_wraps_idat_chunk() {
        let path = unique_path("archive", "zip");
        let mut raw = vec![0u8; 30];
        raw[0..4].copy_from_slice(b"PK\x03\x04");
        write_test_file(&path, &raw);

        let wrapped = read_file(&path, FileTypeCheck::ArchiveFile).expect("archive should read");
        assert_eq!(&wrapped[0..8], &[0, 0, 0, 0, b'I', b'D', b'A', b'T']);
        assert_eq!(&wrapped[8..12], b"PK\x03\x04");
        assert_eq!(wrapped.len(), raw.len() + 12);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cover_image_checks_enforced() {
        let path = unique_path("cover", "png");
        write_test_file(&path, &[0u8; 87]);
        let image = read_file(&path, FileTypeCheck::CoverImage).expect("image should read");
        assert_eq!(image.len(), 87);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn write_output_respects_force() {
        let path = unique_path("out", "png");
        let first = vec![1u8, 2, 3];
        let second = vec![9u8, 8, 7, 6];

        let written = write_polyglot_file(&first, true, Some(&path), false).expect("first write");
        assert_eq!(written, path);
        assert_eq!(std::fs::read(&written).expect("read"), first);

        let err = write_polyglot_file(&second, true, Some(&written), false).expect_err("must fail");
        assert!(err.contains("already exists"));

        write_polyglot_file(&second, true, Some(&written), true).expect("force overwrite");
        assert_eq!(std::fs::read(&written).expect("read"), second);

        let _ = std::fs::remove_file(written);
    }
}
