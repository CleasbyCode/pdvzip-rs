use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
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

    let Some(filename) = path.file_name() else {
        return false;
    };

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = filename.as_bytes();
        !bytes.is_empty() && !bytes.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)
    }

    #[cfg(not(unix))]
    {
        let Some(filename) = filename.to_str() else {
            return false;
        };
        !filename.is_empty() && !filename.chars().any(char::is_control)
    }
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

    let mut open_options = OpenOptions::new();
    open_options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = open_options
        .open(path)
        .map_err(|err| format!("Failed to open file: {} ({err})", path.display()))?;

    // Validate metadata from the descriptor we actually read. This avoids the
    // path-based stat/open race and, on Linux, O_NOFOLLOW rejects symlink inputs.
    let metadata = file
        .metadata()
        .map_err(|err| format!("Error: Failed to stat \"{}\": {err}", path.display()))?;
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
            const MAX_ARCHIVE_SIZE: usize = i32::MAX as usize;
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

    let mut data = Vec::<u8>::new();
    data.try_reserve_exact(buffer_size)
        .map_err(|_| "Error: Unable to allocate file input buffer.".to_string())?;
    data.resize(buffer_size, 0);
    if wrap_archive {
        data[..prefix_size].copy_from_slice(&IDAT_MARKER_BYTES);
    }

    file.read_exact(&mut data[prefix_size..prefix_size + file_size])
        .map_err(|_| "Failed to read full file: partial read".to_string())?;

    if wrap_archive
        && (data.len() < prefix_size + ARCHIVE_SIG.len()
            || data[prefix_size..prefix_size + ARCHIVE_SIG.len()] != ARCHIVE_SIG)
    {
        return Err(
            "Archive File Error: Signature check failure. Not a valid archive file.".to_string(),
        );
    }

    Ok(data)
}

fn open_new_output(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn write_file_contents(mut file: File, path: &Path, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    set_output_permissions(&file, path)?;
    file.sync_all()
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    File::open(output_parent(path))?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn write_temporary_output(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let parent = output_parent(path);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    const MAX_TEMP_ATTEMPTS: usize = 256;
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        // Keep temporary names independent of the destination basename so
        // valid names close to NAME_MAX remain replaceable.
        let temp_path = parent.join(format!(
            ".pdvzip-tmp-{}-{seed:016x}-{attempt:02x}",
            std::process::id(),
        ));
        let file = match open_new_output(&temp_path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };

        if let Err(err) = write_file_contents(file, &temp_path, bytes) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        return Ok(temp_path);
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to create a unique temporary output file",
    ))
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to replace a symlink or non-regular output path",
            ));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let temp_path = write_temporary_output(path, bytes)?;
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    sync_parent_directory(path)
}

fn atomic_create(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp_path = write_temporary_output(path, bytes)?;
    if let Err(err) = fs::hard_link(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Err(err) = fs::remove_file(&temp_path) {
        // The destination is already complete; do not risk deleting a path
        // that another process may have replaced during this rare failure.
        let _ = sync_parent_directory(path);
        return Err(err);
    }
    sync_parent_directory(path)
}

fn write_exact(path: &Path, bytes: &[u8], force: bool) -> io::Result<()> {
    if force {
        return atomic_replace(path, bytes);
    }

    atomic_create(path, bytes)
}

#[cfg(unix)]
fn set_output_permissions(file: &File, _path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_output_permissions(_file: &File, _path: &Path) -> io::Result<()> {
    Ok(())
}

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
        match write_exact(path, image_data, force) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists && !force => {
                return Err(
                    "Write File Error: Output file already exists. Use --force to overwrite."
                        .to_string(),
                );
            }
            Err(err) => {
                return Err(format!(
                    "Write File Error: Failed to write output file: {err}"
                ));
            }
        }
        return Ok(path.to_path_buf());
    }

    const MAX_NAME_ATTEMPTS: usize = 256;
    let prefix = if is_zip_file { "pzip_" } else { "pjar_" };

    let mut seed = {
        let mut random_bytes = [0u8; 8];
        if File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut random_bytes))
            .is_ok()
        {
            u64::from_le_bytes(random_bytes)
        } else {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes();
            let mut fallback = u64::from(std::process::id());
            for (index, byte) in nanos.iter().enumerate() {
                fallback ^= u64::from(*byte) << ((index % 8) * 8);
            }
            fallback
        }
    };

    for _ in 0..MAX_NAME_ATTEMPTS {
        let number = 10_000 + (seed % 90_000);
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);

        let candidate = PathBuf::from(format!("{prefix}{number}.png"));
        match write_exact(&candidate, image_data, false) {
            Ok(()) => {
                return Ok(candidate);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "Write File Error: Failed to write output file: {err}"
                ));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn input_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let target = unique_path("cover_target", "png");
        let link = unique_path("cover_link", "png");
        write_test_file(&target, &[0u8; 87]);
        symlink(&target, &link).expect("create symlink");

        let err = read_file(&link, FileTypeCheck::CoverImage).expect_err("symlink must fail");
        assert!(err.contains("Failed to open file"));

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forced_output_does_not_follow_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let target = unique_path("output_target", "data");
        let link = unique_path("output_link", "png");
        write_test_file(&target, b"unchanged");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("set target mode");
        symlink(&target, &link).expect("create symlink");

        assert!(write_polyglot_file(b"replacement", true, Some(&link), true).is_err());
        assert_eq!(std::fs::read(&target).expect("target bytes"), b"unchanged");
        assert_eq!(
            std::fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }

    #[cfg(unix)]
    #[test]
    fn forced_output_atomically_replaces_instead_of_mutating_hard_links() {
        let output = unique_path("atomic_output", "png");
        let peer = unique_path("atomic_peer", "data");
        write_test_file(&output, b"original");
        std::fs::hard_link(&output, &peer).expect("create hard link");

        write_polyglot_file(b"replacement", true, Some(&output), true).expect("atomic replacement");
        assert_eq!(std::fs::read(&output).expect("new output"), b"replacement");
        assert_eq!(std::fs::read(&peer).expect("old hard link"), b"original");

        let _ = std::fs::remove_file(output);
        let _ = std::fs::remove_file(peer);
    }

    #[cfg(unix)]
    #[test]
    fn forced_output_supports_destination_names_near_name_max() {
        let directory = unique_path("long_output_directory", "dir");
        std::fs::create_dir(&directory).expect("create test directory");
        let filename = format!("{}.png", "x".repeat(240));
        let output = directory.join(filename);
        write_test_file(&output, b"original");

        write_polyglot_file(b"replacement", true, Some(&output), true)
            .expect("replace long filename");
        assert_eq!(std::fs::read(&output).expect("replacement"), b"replacement");

        let _ = std::fs::remove_file(output);
        let _ = std::fs::remove_dir(directory);
    }

    #[test]
    fn archive_limit_matches_png_chunk_limit() {
        let path = unique_path("oversized_sparse", "zip");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create sparse archive");
        file.set_len(i32::MAX as u64 + 1)
            .expect("size sparse archive");
        drop(file);

        let err = read_file(&path, FileTypeCheck::ArchiveFile).expect_err("oversized archive");
        assert!(err.contains("exceeds maximum size limit"));
        let _ = std::fs::remove_file(path);
    }
}
