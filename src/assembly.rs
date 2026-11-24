use crate::binary_utils::{self, ByteOrder, write_value_at};
use crc32fast::Hasher;

pub type AssemblyResult<T> = Result<T, String>;

const ZIP_LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const CENTRAL_DIR_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];

fn read_le16(data: &[u8], offset: usize) -> AssemblyResult<u16> {
    binary_utils::read_le16(data, offset).map_err(|err| format!("ZIP Error: {err}"))
}

fn read_le32(data: &[u8], offset: usize) -> AssemblyResult<u32> {
    binary_utils::read_le32(data, offset).map_err(|err| format!("ZIP Error: {err}"))
}

fn write_le16(data: &mut [u8], offset: usize, value: u16) -> AssemblyResult<()> {
    binary_utils::write_le16(data, offset, value).map_err(|err| format!("ZIP Error: {err}"))
}

fn write_le32(data: &mut [u8], offset: usize, value: u32) -> AssemblyResult<()> {
    binary_utils::write_le32(data, offset, value).map_err(|err| format!("ZIP Error: {err}"))
}

/// Rebases every ZIP offset onto the archive's position in the output image and
/// returns the EOCD record's index there.
fn fix_zip_offsets(
    image_vec: &mut [u8],
    original_image_size: usize,
    script_data_size: usize,
) -> AssemblyResult<usize> {
    const ZIP_BASE_SHIFT: usize = 8;
    const PNG_TRAILING_BYTES: usize = 16;

    let zip_base_offset = binary_utils::checked_add(
        binary_utils::checked_add(
            original_image_size,
            script_data_size,
            "ZIP Error: Base offset overflow.",
        )?,
        ZIP_BASE_SHIFT,
        "ZIP Error: Base offset overflow.",
    )?;

    if image_vec.len() < PNG_TRAILING_BYTES {
        return Err("ZIP Error: Embedded image is truncated.".to_string());
    }
    let zip_end_offset = image_vec.len() - PNG_TRAILING_BYTES;
    // Re-check the EOCD at the mutation boundary.
    let directory = binary_utils::read_zip_central_directory(
        image_vec,
        zip_base_offset,
        zip_end_offset,
        "ZIP Error",
    )?;
    let central_start = directory.start;
    let central_end = directory.end;
    if central_start > u32::MAX as usize {
        return Err("ZIP Error: Central directory offset exceeds ZIP32 limits.".to_string());
    }
    if usize::from(directory.eocd_comment_length) > (u16::MAX as usize - PNG_TRAILING_BYTES) {
        return Err("ZIP Error: Comment length overflow.".to_string());
    }

    write_le16(
        image_vec,
        directory.eocd_index + binary_utils::ZIP_EOCD_COMMENT_LENGTH_OFFSET,
        (usize::from(directory.eocd_comment_length) + PNG_TRAILING_BYTES) as u16,
    )?;
    write_le32(
        image_vec,
        directory.eocd_index + binary_utils::ZIP_EOCD_CENTRAL_OFFSET,
        central_start as u32,
    )?;

    let mut cursor = central_start;
    for record_index in 0..usize::from(directory.total_records) {
        if cursor > image_vec.len() || binary_utils::ZIP_CENTRAL_RECORD_MIN_SIZE > image_vec.len() - cursor {
            return Err("ZIP Error: Truncated central directory file header.".to_string());
        }
        if image_vec[cursor..cursor + CENTRAL_DIR_SIG.len()] != CENTRAL_DIR_SIG {
            return Err(format!(
                "ZIP Error: Invalid central directory file header signature at record {}.",
                record_index + 1
            ));
        }

        let name_length = read_le16(image_vec, cursor + binary_utils::ZIP_CENTRAL_NAME_LENGTH_OFFSET)? as usize;
        let extra_length = read_le16(image_vec, cursor + binary_utils::ZIP_CENTRAL_EXTRA_LENGTH_OFFSET)? as usize;
        let comment_length = read_le16(image_vec, cursor + binary_utils::ZIP_CENTRAL_COMMENT_LENGTH_OFFSET)? as usize;
        let entry_disk_start = read_le16(image_vec, cursor + binary_utils::ZIP_CENTRAL_DISK_START)?;
        let record_size = binary_utils::zip_central_directory_record_size(
            name_length,
            extra_length,
            comment_length,
        )?;

        if entry_disk_start != 0 {
            return Err(format!(
                "ZIP Error: Multi-disk local header reference on record {} is not supported.",
                record_index + 1
            ));
        }
        if record_size > image_vec.len() - cursor || cursor + record_size > central_end {
            return Err("ZIP Error: Central directory entry exceeds archive bounds.".to_string());
        }

        let local_offset = binary_utils::checked_add(
            zip_base_offset,
            read_le32(image_vec, cursor + binary_utils::ZIP_CENTRAL_LOCAL_OFFSET)? as usize,
            "ZIP Error: Local file header offset overflow.",
        )?;
        if local_offset > u32::MAX as usize {
            return Err("ZIP Error: Local file header offset exceeds ZIP32 limits.".to_string());
        }
        if local_offset >= central_start || 4 > image_vec.len() - local_offset {
            return Err("ZIP Error: Local file header offset is out of bounds.".to_string());
        }
        if image_vec[local_offset..local_offset + ZIP_LOCAL_SIG.len()] != ZIP_LOCAL_SIG {
            return Err(format!(
                "ZIP Error: Local file header signature mismatch for record {}.",
                record_index + 1
            ));
        }

        write_le32(
            image_vec,
            cursor + binary_utils::ZIP_CENTRAL_LOCAL_OFFSET,
            local_offset as u32,
        )?;
        cursor += record_size;
    }

    if cursor != central_end {
        return Err("ZIP Error: Central directory size does not match parsed records.".to_string());
    }

    Ok(directory.eocd_index)
}

pub fn embed_chunks(
    image_vec: &mut Vec<u8>,
    mut script_vec: Vec<u8>,
    mut archive_vec: Vec<u8>,
    original_image_size: usize,
) -> AssemblyResult<()> {
    const ICCP_CHUNK_INDEX: usize = 0x21;
    const VALUE_BYTE_LENGTH_FOUR: usize = 4;
    const ARCHIVE_INSERT_INDEX_DIFF: usize = 12;
    const EXCLUDE_SIZE_AND_CRC_LENGTH: usize = 8;
    const LAST_IDAT_INDEX_DIFF: usize = 4;
    const LAST_IDAT_CRC_INDEX_DIFF: usize = 16;
    const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;

    if script_vec.len() < CHUNK_FIELDS_COMBINED_LENGTH {
        return Err("Script Error: iCCP chunk is truncated.".to_string());
    }
    if image_vec.len() < ICCP_CHUNK_INDEX {
        return Err("PNG Error: Cover image is too small for iCCP insertion.".to_string());
    }
    if image_vec.len() < ARCHIVE_INSERT_INDEX_DIFF {
        return Err("PNG Error: Cover image is truncated before IEND.".to_string());
    }
    if archive_vec.len() < CHUNK_FIELDS_COMBINED_LENGTH {
        return Err("ZIP Error: Archive data is truncated.".to_string());
    }

    let script_data_size = script_vec.len() - CHUNK_FIELDS_COMBINED_LENGTH;
    let archive_file_size = archive_vec.len();

    let additional_size = script_vec
        .len()
        .checked_add(archive_vec.len())
        .ok_or_else(|| "Embed Error: Output image size overflow.".to_string())?;
    image_vec
        .try_reserve_exact(additional_size)
        .map_err(|_| "Embed Error: Unable to allocate output image buffer.".to_string())?;

    image_vec.splice(ICCP_CHUNK_INDEX..ICCP_CHUNK_INDEX, script_vec.drain(..));
    let archive_insert_index = image_vec.len() - ARCHIVE_INSERT_INDEX_DIFF;
    image_vec.splice(
        archive_insert_index..archive_insert_index,
        archive_vec.drain(..),
    );

    let eocd_index = fix_zip_offsets(image_vec, original_image_size, script_data_size)?;

    let last_idat_index = binary_utils::checked_add(
        binary_utils::checked_add(
            original_image_size,
            script_data_size,
            "ZIP Error: Size overflow while computing CRC start.",
        )?,
        LAST_IDAT_INDEX_DIFF,
        "ZIP Error: Size overflow while computing CRC start.",
    )?;
    let crc_len = archive_file_size - EXCLUDE_SIZE_AND_CRC_LENGTH;
    let crc_end = binary_utils::checked_add(
        last_idat_index,
        crc_len,
        "ZIP Error: Size overflow while computing CRC range.",
    )?;
    if crc_end > image_vec.len() {
        return Err("ZIP Error: Invalid IDAT CRC range.".to_string());
    }

    let mut hasher = Hasher::new();
    hasher.update(&image_vec[last_idat_index..crc_end]);
    let last_idat_crc = hasher.finalize();

    let complete_size = image_vec.len();
    if complete_size < LAST_IDAT_CRC_INDEX_DIFF {
        return Err("ZIP Error: Output is truncated before final IDAT CRC.".to_string());
    }
    let crc_index = complete_size - LAST_IDAT_CRC_INDEX_DIFF;
    write_value_at(
        image_vec,
        crc_index,
        last_idat_crc as usize,
        VALUE_BYTE_LENGTH_FOUR,
        ByteOrder::Big,
    )
    .map_err(|err| format!("ZIP Error: {err}"))?;

    ensure_eocd_is_still_selected(image_vec, eocd_index)
}

/// `find_zip_eocd_locator` checked the archive as the user supplied it, but the
/// bytes written since then can spell a signature that extractors would act on:
/// rebasing rewrote the EOCD's comment length and central directory offset and
/// every record's local header offset (the last record's sits 20 bytes before
/// the EOCD, where a ZIP64 locator would be read), and the final CRC and IEND
/// chunk extend the comment to the end of the file. Re-check the final bytes:
/// no EOCD signature may follow the real record, since Info-ZIP and others take
/// the last one, and no ZIP64 locator may precede it.
fn ensure_eocd_is_still_selected(image_vec: &[u8], eocd_index: usize) -> AssemblyResult<()> {
    const PNG_TRAILING_BYTES: usize = 4 + 12; // IDAT CRC + IEND
    const ZIP64_LOCATOR_SIZE: usize = 20;
    let crc_index = image_vec.len() - PNG_TRAILING_BYTES;
    if let Some(offset) = image_vec[eocd_index + 1..]
        .windows(4)
        .position(|window| window == b"PK\x05\x06")
    {
        return Err(if eocd_index + 1 + offset + 4 <= crc_index {
            "Embed Error: Rebasing the archive's offsets for this cover image forms a second ZIP \
end-of-central-directory signature. Change the archive (or its comment) or the cover image and try again."
        } else {
            "Embed Error: The final IDAT CRC forms a ZIP end-of-central-directory signature. \
Change the archive or cover image slightly and try again."
        }
        .to_string());
    }
    if eocd_index >= ZIP64_LOCATOR_SIZE
        && image_vec[eocd_index - ZIP64_LOCATOR_SIZE..eocd_index - ZIP64_LOCATOR_SIZE + 4] == *b"PK\x06\x07"
    {
        return Err("Embed Error: Rebasing the archive's offsets for this cover image forms a ZIP64 \
locator signature before the end-of-central-directory record. Change the archive or the cover image \
and try again."
            .to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::embed_chunks;
    use crate::binary_utils::{ByteOrder, read_value_at, write_value_at};

    fn base_image() -> Vec<u8> {
        include_bytes!("../tests/fixtures/assembly_base_image.bin").to_vec()
    }

    fn base_image_size() -> usize {
        include_str!("../tests/fixtures/assembly_base_image_size.txt")
            .trim()
            .parse()
            .expect("base image size fixture must parse")
    }

    #[test]
    fn parity_zip_video_fixture() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let archive = include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let expected = include_bytes!("../tests/fixtures/assembly_zip_video.out.bin").to_vec();

        embed_chunks(&mut image, script, archive, base_image_size()).expect("embed zip fixture");
        assert_eq!(image, expected);
    }

    #[test]
    fn parity_jar_fixture() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_jar_manifest.script.bin").to_vec();
        let archive =
            include_bytes!("../tests/fixtures/assembly_jar_manifest.archive.bin").to_vec();
        let expected = include_bytes!("../tests/fixtures/assembly_jar_manifest.out.bin").to_vec();

        embed_chunks(&mut image, script, archive, base_image_size()).expect("embed jar fixture");
        assert_eq!(image, expected);
    }

    #[test]
    fn rejects_truncated_script_chunk() {
        let mut image = vec![0u8; 64];
        let script = vec![0u8; 11];
        let archive = vec![0u8; 12];
        let err =
            embed_chunks(&mut image, script, archive, 0).expect_err("expected truncation error");
        assert!(err.contains("iCCP chunk is truncated"));
    }

    #[test]
    fn rejects_archive_without_eocd() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        // The archive buffer includes the 12-byte PNG chunk wrapper. Keep the
        // payload large enough for a minimum ZIP EOCD so this specifically
        // exercises the missing-signature path instead of wrapper truncation.
        let archive = vec![0u8; 34];
        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("expected EOCD lookup failure");
        assert!(err.contains("ZIP Error: End of central directory record not found"), "{err}");
    }

    #[test]
    fn rejects_incomplete_archive_chunk_wrapper() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let archive = vec![0u8; 11];
        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("expected wrapper truncation");
        assert!(err.contains("Archive data is truncated"));
    }

    #[test]
    fn rejects_eocd_gap_before_png_trailer() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let mut archive =
            include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        archive.insert(archive.len() - 4, 0x41);

        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("EOCD comment must end exactly at archive boundary");
        assert!(err.contains("ZIP Error: End of central directory record not found"), "{err}");
    }

    #[test]
    fn rejects_multidisk_metadata_during_rebase() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let mut archive =
            include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let eocd = archive
            .windows(4)
            .rposition(|window| window == b"PK\x05\x06")
            .expect("EOCD");
        archive[eocd + 4..eocd + 6].copy_from_slice(&1u16.to_le_bytes());

        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("multi-disk archive must fail");
        assert!(err.contains("ZIP Error: Multi-disk ZIP archives are not supported"), "{err}");
    }

    #[test]
    fn rejects_central_entry_disk_start_during_rebase() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let mut archive =
            include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let central = archive
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("central record");
        archive[central + 34..central + 36].copy_from_slice(&1u16.to_le_bytes());

        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("entry disk start must fail");
        assert!(err.contains("Multi-disk local header reference"));
    }

    /// A one-entry stored ZIP in its 12-byte IDAT chunk wrapper.
    fn wrapped_zip(name: &str, comment: &[u8]) -> Vec<u8> {
        let payload = b"x";
        let crc = crc32fast::hash(payload);
        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        for value in [20u16, 0, 0, 0, 0] {
            zip.extend_from_slice(&value.to_le_bytes());
        }
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name.as_bytes());
        zip.extend_from_slice(payload);
        let central_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        for value in [0x0314u16, 20, 0, 0, 0, 0] {
            zip.extend_from_slice(&value.to_le_bytes());
        }
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        for value in [name.len() as u16, 0, 0, 0, 0] {
            zip.extend_from_slice(&value.to_le_bytes());
        }
        zip.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name.as_bytes());
        let central_size = zip.len() as u32 - central_offset;
        zip.extend_from_slice(b"PK\x05\x06");
        for value in [0u16, 0, 1, 1] {
            zip.extend_from_slice(&value.to_le_bytes());
        }
        zip.extend_from_slice(&central_size.to_le_bytes());
        zip.extend_from_slice(&central_offset.to_le_bytes());
        zip.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        zip.extend_from_slice(comment);

        let mut wrapped = Vec::with_capacity(zip.len() + 12);
        wrapped.extend_from_slice(&(zip.len() as u32).to_be_bytes());
        wrapped.extend_from_slice(b"IDAT");
        wrapped.extend_from_slice(&zip);
        wrapped.extend_from_slice(&[0; 4]);
        wrapped
    }

    /// Rebasing rewrites bytes inside and just before the EOCD record after the
    /// archive was validated; none of them may spell a signature that an
    /// extractor would act on instead of the real record.
    #[test]
    fn rebased_offsets_cannot_form_signatures() {
        const IEND: [u8; 12] = [0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];
        let script = vec![0x55u8; 20];
        let cover = |size: usize| {
            let mut image = vec![0xAAu8; size];
            image[size - 12..].copy_from_slice(&IEND);
            image
        };
        // The ZIP data starts here once the archive chunk is inserted.
        let cover_size_for_base = |zip_base: usize| zip_base - (script.len() - 12) - 8;
        let embed = |image_size: usize, archive: Vec<u8>| {
            let mut image = cover(image_size);
            embed_chunks(&mut image, script.clone(), archive, image_size)
        };
        let small = 0x21 + 12;

        // The comment length grows by 16: 0x4B40 becomes 0x4B50 ("PK"), so a
        // comment starting 05 06 completes a signature at EOCD + 20.
        let mut comment = vec![0u8; 0x4B40];
        comment[..2].copy_from_slice(&[0x05, 0x06]);
        let err = embed(small, wrapped_zip("main.py", &comment)).expect_err("EOCD + 20");
        assert!(err.contains("end-of-central-directory signature"), "{err}");
        // 0x4FF0 becomes 0x5000: its high byte is the 'P', at EOCD + 21.
        let mut comment = vec![0u8; 0x4FF0];
        comment[..3].copy_from_slice(&[0x4B, 0x05, 0x06]);
        let err = embed(small, wrapped_zip("main.py", &comment)).expect_err("EOCD + 21");
        assert!(err.contains("end-of-central-directory signature"), "{err}");
        // The same lengths with other comment bytes are fine.
        embed(small, wrapped_zip("main.py", &[0u8; 0x4B40])).expect("plain 0x4B40 comment");
        embed(small, wrapped_zip("main.py", &[0u8; 0x4FF0])).expect("plain 0x4FF0 comment");

        // A central directory rebased to 0x06054B50 writes the signature itself
        // into the EOCD's offset field (EOCD + 16). The local header, the name
        // and the one-byte payload come first.
        const CENTRAL_RELATIVE_OFFSET: usize = 30 + 7 + 1;
        let err = embed(
            cover_size_for_base(0x0605_4B50 - CENTRAL_RELATIVE_OFFSET),
            wrapped_zip("main.py", &[]),
        )
        .expect_err("central offset");
        assert!(err.contains("end-of-central-directory signature"), "{err}");

        // The last record's local header offset sits 20 bytes before the EOCD
        // when its name, extra field and comment total 16 bytes: rebased to
        // 0x07064B50 it reads as a ZIP64 locator.
        let err = embed(
            cover_size_for_base(0x0706_4B50),
            wrapped_zip("sixteen_name.txt", &[]),
        )
        .expect_err("ZIP64 locator");
        assert!(err.contains("ZIP64 locator"), "{err}");
    }

    #[test]
    fn rewrites_zip_offsets_to_rebased_locations() {
        const EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
        const CENTRAL_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
        const LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

        let mut image = base_image();
        let original_image_size = image.len();

        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let mut archive =
            include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let archive_data_len = archive.len() - 12;
        write_value_at(&mut archive, 0, archive_data_len, 4, ByteOrder::Big)
            .expect("archive length update");

        embed_chunks(&mut image, script, archive, original_image_size).expect("embed");

        let eocd_index = image
            .windows(EOCD_SIG.len())
            .rposition(|window| window == EOCD_SIG)
            .expect("EOCD");

        assert_eq!(
            read_value_at(&image, eocd_index + 20, 2, ByteOrder::Little).expect("comment"),
            16
        );
        let total_records =
            read_value_at(&image, eocd_index + 10, 2, ByteOrder::Little).expect("records");
        assert!(total_records >= 1);

        let central_start =
            read_value_at(&image, eocd_index + 16, 4, ByteOrder::Little).expect("central start");
        assert!(central_start > original_image_size);

        let mut cursor = central_start;
        for _ in 0..total_records {
            assert!(cursor + 46 <= image.len());
            assert_eq!(&image[cursor..cursor + 4], &CENTRAL_SIG);

            let local_offset =
                read_value_at(&image, cursor + 42, 4, ByteOrder::Little).expect("local offset");
            assert!(local_offset + 30 <= image.len());
            assert_eq!(&image[local_offset..local_offset + 4], &LOCAL_SIG);

            let name_length =
                read_value_at(&image, cursor + 28, 2, ByteOrder::Little).expect("name length");
            let extra_length =
                read_value_at(&image, cursor + 30, 2, ByteOrder::Little).expect("extra length");
            let comment_length =
                read_value_at(&image, cursor + 32, 2, ByteOrder::Little).expect("comment len");
            cursor += 46 + name_length + extra_length + comment_length;
        }

        assert_eq!(cursor, eocd_index);
    }
}
